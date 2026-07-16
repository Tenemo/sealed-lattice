import { webcrypto } from 'node:crypto';

import { shake256 } from '@noble/hashes/sha3.js';
import { foundationProfile, stateCapabilityKinds } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    abortVerifiedCommonProofApplication,
    CommonProofWorkerRuntimeError,
    confirmVerifiedCommonProofApplication,
    decodeCommonProofExternalMemoryRequest,
    encodeCommonProofExternalMemoryResponse,
    openClosedWorkerCommonProofGenerationFamilyAdapter,
    openClosedWorkerCommonProofVerificationFamilyAdapter,
    prepareVerifiedCommonProofApplication,
    releaseClosedWorkerCommonProofGenerationFamilyAdapter,
    runClosedWorkerCommonProofGenerationFamilyAdapter,
    runClosedWorkerCommonProofVerificationFamilyAdapter,
    runPreparedCommonProofGenerationWorker,
    runPreparedCommonProofVerificationWorker,
    type AuthenticatedCommonProofInputStore,
    type CommonProofCanonicalOutputStore,
    type CommonProofExternalMemoryReadResult,
    type CommonProofExternalMemoryTransactionExecutor,
    type CommonProofGenerationWorkerOptions,
    type CommonProofGenerationCheckpoint,
    type CommonProofApplicationFreshnessCoordinate,
    type CommonProofApplicationStorageRootAccess,
    type CommonProofVerificationWorkerOptions,
    type VerifiedCommonProofCapability,
} from '../../src/common-proof-worker-runtime.js';
import {
    createWasmBrowserActionStorageWorkerKernel,
    loadFreshTranscriptCoreKernel,
} from '../../src/index.js';
import {
    openStateVerifierSession,
    type StateVerifierSession,
    type VerifiedStateDurableBinding,
} from '../../src/state-verifier-runtime.js';
import { registerCommonProofKernelContext } from '../../src/transcript-core-bridge/common-proof-kernel-context.js';
import type { TranscriptCoreKernelCommandRuntime } from '../../src/transcript-core-bridge/kernel-runtime.js';
import type {
    TranscriptCoreKernel,
    TranscriptCoreKernelExports,
} from '../../src/transcript-core-bridge/kernel-types.js';

import {
    createCanonicalCarrierSigningKeyPairFixtures,
    signCanonicalCarrierFixtureMessage,
} from '#packages/crypto/tests/support/canonical-carrier-signature-fixtures';
import { openAuthenticatedCheckpointStore } from '#packages/protocol/src/runtime/authenticated-checkpoint-store';
import type {
    BrowserActionStorageCustody,
    BrowserActionStorageRootBinding,
    BrowserFoundationFreshnessCoordinate,
} from '#packages/protocol/src/runtime/browser-action-storage-custody';
import {
    closeCommonProofExecutionEnvironmentInInstalledCustodyWorker,
    copyInstalledCommonProofCheckpointResumeDescriptor,
    installBrowserActionStorageCustodyWorkerHost,
    openCommonProofExecutionEnvironmentInInstalledCustodyWorker,
    prepareCommonProofGenerationInInstalledCustodyWorker,
    runCommonProofGenerationInInstalledCustodyWorker,
    suspendCommonProofExecutionEnvironmentForAuthenticatedResumeInInstalledCustodyWorker,
    verifyAndApplyCommonProofInInstalledCustodyWorker,
    type BrowserActionStorageCustodyWorkerConfiguration,
} from '#packages/protocol/src/runtime/browser-action-storage-custody-worker-channel';
import type { BrowserFoundationInitializationInput } from '#packages/protocol/src/runtime/browser-foundation-operation-owner';
import {
    commonProofApplicationHandoffLogicalRecordKey,
    deriveCommonProofAttemptLogicalRecordPrefix,
    openCommonProofBrowserCustody,
    type CommonProofBrowserCustody,
} from '#packages/protocol/src/runtime/common-proof-browser-custody';
import {
    openDurableStateWitnessService,
    type DurableStateWitnessServiceLimits,
} from '#packages/protocol/src/runtime/durable-state-witness-service';
import type {
    WebLockCommittedBrowserFoundationInitialization,
    WebLockFoundationWitnessRecord,
    WebLockOwnedBrowserActionStorageCustody,
    WebLockOwnedFoundationWitnessRole,
} from '#packages/protocol/src/runtime/web-lock-owned-untrusted-storage-transaction-store';
import { commonProofStorageCapacityProfile } from '#packages/protocol/src/runtime/web-lock-owned-untrusted-storage-transaction-store';
import {
    generateRuntimeStorageEncryptionKey,
    openRuntimeTestStore,
    runtimeAuthorityContext,
} from '#packages/protocol/tests/support/runtime-storage-test-support';
import {
    asciiItem,
    canonicalItem,
    canonicalTuple,
    concatenateBytes,
    foundationHash512,
    hashItem,
    unsigned16LittleEndian,
    unsigned32LittleEndian,
    unsigned64Item,
    variableBytesItem,
} from '#packages/wasm/tests/canonical-tuple-test-helpers';
import { createStateVerifierTestVector } from '#packages/wasm/tests/state-verifier-test-vectors';

const hashByteLength = 64;
const cryptoProvider = webcrypto as unknown as Crypto;
const requestHeaderByteLength = 156;
const requestDigestOffset = 92;
const operationHeaderByteLength = 32;
const hashPrefix = new TextEncoder().encode('sealed.vote/hash512');
const requestDigestDomain =
    'sealed-lattice/common-proof/external-memory-request/v1';

type EncodedOperation = Readonly<{
    encodedOrdinal?: number;
    kind: number;
    objectOrdinal: number;
    payload?: Uint8Array;
    payloadByteLength: bigint;
    position: bigint;
    protection: number;
}>;

const varuint = (input: bigint): Uint8Array => {
    const output: number[] = [];
    let remaining = input;
    do {
        let byte = Number(remaining & 0x7fn);
        remaining >>= 7n;
        if (remaining !== 0n) {
            byte |= 0x80;
        }
        output.push(byte);
    } while (remaining !== 0n);
    return Uint8Array.from(output);
};

const hashFramedParts = (
    domain: string,
    parts: readonly Uint8Array[],
): Uint8Array => {
    const hash = shake256.create({ dkLen: hashByteLength });
    const domainBytes = new TextEncoder().encode(domain);
    hash.update(hashPrefix);
    hash.update(varuint(BigInt(domainBytes.byteLength)));
    hash.update(domainBytes);
    hash.update(varuint(BigInt(parts.length)));
    for (const part of parts) {
        hash.update(varuint(BigInt(part.byteLength)));
        hash.update(part);
    }
    return hash.digest();
};

const littleEndianBytes = (
    byteLength: 2 | 4 | 8,
    value: number | bigint,
): Uint8Array => {
    const bytes = new Uint8Array(byteLength);
    const view = new DataView(bytes.buffer);
    if (byteLength === 2) {
        view.setUint16(0, Number(value), true);
    } else if (byteLength === 4) {
        view.setUint32(0, Number(value), true);
    } else {
        view.setBigUint64(0, BigInt(value), true);
    }
    return bytes;
};

const encodeOperations = (
    operations: readonly EncodedOperation[],
): Uint8Array => {
    const byteLength = operations.reduce(
        (total, operation) =>
            total +
            operationHeaderByteLength +
            (operation.payload?.byteLength ?? 0),
        0,
    );
    const bytes = new Uint8Array(byteLength);
    const view = new DataView(bytes.buffer);
    let offset = 0;
    for (const [operationIndex, operation] of operations.entries()) {
        view.setUint32(
            offset,
            operation.encodedOrdinal ?? operationIndex,
            true,
        );
        offset += 4;
        view.setUint16(offset, operation.kind, true);
        offset += 2;
        view.setUint16(offset, operation.protection, true);
        offset += 2;
        view.setUint32(offset, operation.objectOrdinal, true);
        offset += 4;
        view.setUint32(offset, 0, true);
        offset += 4;
        view.setBigUint64(offset, operation.position, true);
        offset += 8;
        view.setBigUint64(offset, operation.payloadByteLength, true);
        offset += 8;
        if (operation.payload !== undefined) {
            bytes.set(operation.payload, offset);
            offset += operation.payload.byteLength;
        }
    }
    expect(offset).toBe(bytes.byteLength);
    return bytes;
};

const encodeRequest = (input: {
    maximumOperationCount?: number;
    maximumPayloadByteLength: bigint;
    operations: readonly EncodedOperation[];
    requestSequence: bigint;
    runtimeBindingHash: Uint8Array;
}): Uint8Array<ArrayBuffer> => {
    const maximumOperationCount =
        input.maximumOperationCount ?? input.operations.length;
    const operationBytes = encodeOperations(input.operations);
    const digest = hashFramedParts(requestDigestDomain, [
        littleEndianBytes(2, 1),
        input.runtimeBindingHash,
        littleEndianBytes(8, input.requestSequence),
        littleEndianBytes(8, input.maximumPayloadByteLength),
        littleEndianBytes(4, maximumOperationCount),
        littleEndianBytes(4, input.operations.length),
        operationBytes,
    ]);
    const request = new Uint8Array(
        requestHeaderByteLength + operationBytes.byteLength,
    );
    const view = new DataView(request.buffer);
    let offset = 0;
    view.setUint16(offset, 1, true);
    offset += 2;
    view.setUint16(offset, 1, true);
    offset += 2;
    view.setBigUint64(offset, input.maximumPayloadByteLength, true);
    offset += 8;
    view.setUint32(offset, maximumOperationCount, true);
    offset += 4;
    view.setUint32(offset, input.operations.length, true);
    offset += 4;
    view.setBigUint64(offset, input.requestSequence, true);
    offset += 8;
    request.set(input.runtimeBindingHash, offset);
    offset += hashByteLength;
    request.set(digest, offset);
    offset += hashByteLength;
    request.set(operationBytes, offset);
    return request;
};

const runtimeBinding = (byte: number): Uint8Array<ArrayBuffer> =>
    new Uint8Array(hashByteLength).fill(byte);
const installedCommonProofVerificationBindingHash = runtimeBinding(0x6b);
const installedProofAttemptLineageIdentifier = new Uint8Array(32).fill(0x7c);

const bytesFromHex = (encoded: string): Uint8Array<ArrayBuffer> => {
    const bytes = new Uint8Array(encoded.length / 2);
    for (let byteIndex = 0; byteIndex < bytes.byteLength; byteIndex += 1) {
        bytes[byteIndex] = Number.parseInt(
            encoded.slice(byteIndex * 2, byteIndex * 2 + 2),
            16,
        );
    }
    return bytes;
};

const fourByteReadRequest = (
    binding: Uint8Array,
    requestSequence: bigint,
): Uint8Array<ArrayBuffer> =>
    encodeRequest({
        maximumPayloadByteLength: 4n,
        operations: [
            {
                kind: 4,
                objectOrdinal: 7,
                payloadByteLength: 4n,
                position: 3n,
                protection: 0,
            },
        ],
        requestSequence,
        runtimeBindingHash: binding,
    });

const readResult = (
    operationIndex: number,
    objectOrdinal: number,
    offset: bigint,
    bytes: number[],
): CommonProofExternalMemoryReadResult => ({
    bytes: Uint8Array.from(bytes),
    objectOrdinal,
    offset,
    operationIndex,
});

const noSecondPollValue = 0xffff_ffff;

const writeUnsigned32 = (
    memory: WebAssembly.Memory,
    pointer: number,
    value: number,
): void => {
    new DataView(memory.buffer).setUint32(pointer, value, true);
};

const memoryBytes = (
    memory: WebAssembly.Memory,
    pointer: number,
    byteLength: number,
): Uint8Array => new Uint8Array(memory.buffer, pointer, byteLength);

const createMockKernelRuntime = (
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

const writeGenerationPoll = (
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

const createCheckpointGenerationKernelFixture = (
    checkpointCursorBytes: readonly Uint8Array[] = [
        Uint8Array.from([1, 3, 3, 7, 9, 2, 5]),
    ],
): Readonly<{
    canonicalStateBytes: Uint8Array<ArrayBuffer>;
    cursorBytes: Uint8Array<ArrayBuffer>;
    observations: {
        acknowledgedCheckpointCount: number;
        discardedCheckpointCount: number;
        retiredOperationCount: number;
    };
    runtime: TranscriptCoreKernelCommandRuntime;
    stableAttemptBindingHash: Uint8Array<ArrayBuffer>;
}> => {
    const canonicalStateBytes = new Uint8Array(37).fill(0x91);
    const cursorBytes = Uint8Array.from(checkpointCursorBytes[0] ?? []);
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
            cursorCountPointer,
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
                cursorCountPointer,
                checkpointCursorBytes.length,
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
        sealed_lattice_common_proof_generation_checkpoint_cursor_byte_length: (
            operationHandle,
            cursorIndex,
            statusPointer,
        ) => {
            expect(operationHandle).toBe(91);
            const selectedCursorBytes = checkpointCursorBytes[cursorIndex];
            if (selectedCursorBytes === undefined) {
                throw new Error('The checkpoint cursor index is unavailable.');
            }
            writeUnsigned32(memory, statusPointer, 0);
            return selectedCursorBytes.byteLength;
        },
        sealed_lattice_common_proof_generation_copy_checkpoint_cursor: (
            operationHandle,
            cursorIndex,
            outputPointer,
            outputByteLength,
        ) => {
            expect(operationHandle).toBe(91);
            const selectedCursorBytes = checkpointCursorBytes[cursorIndex];
            if (selectedCursorBytes === undefined) {
                throw new Error('The checkpoint cursor index is unavailable.');
            }
            expect(outputByteLength).toBe(selectedCursorBytes.byteLength);
            memoryBytes(memory, outputPointer, outputByteLength).set(
                selectedCursorBytes,
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
        cursorBytes,
        observations,
        runtime,
        stableAttemptBindingHash,
    };
};

const createVerifiedApplicationFixture = async (input?: {
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

const foundationWitnessServiceLimits: DurableStateWitnessServiceLimits =
    Object.freeze({
        maximumExactOutputByteLength: 65_536,
        maximumRecordSealingCount: 128,
        maximumSignedVoteCarrierByteLength: 65_536,
        transactionLifetimeMilliseconds: 10_000,
    });

const foundationStorageTransactionLimits = Object.freeze({
    maximumActiveTransactionCount: 2,
    maximumLeaseByteLength:
        commonProofStorageCapacityProfile.maximumLeaseByteLength,
    maximumLeaseCountPerTransaction:
        commonProofStorageCapacityProfile.maximumLeaseCountPerTransaction,
    maximumOwnedRecordCount: 40_000,
    maximumStoredValueByteLength: 320_000_000,
    maximumTransactionByteLength:
        commonProofStorageCapacityProfile.maximumTransactionByteLength,
    maximumTransactionLifetimeMilliseconds: 10_000,
});

const commonProofCheckpointLimits = Object.freeze({
    maximumActiveOperationIdentityCount: 64,
    maximumCheckpointStateByteLength: 1_048_576,
    maximumManifestByteLength: 16_384,
    maximumRandomCursorCount: 8,
    maximumRecordSealingCount: 256,
    maximumSourceDigestCount: 8,
    maximumStreamAttemptCount: 4,
    transactionLifetimeMilliseconds: 10_000,
});

const commonProofCheckpointBoundaryPolicy = Object.freeze({
    validatePublication: () => undefined,
    validateResume: () => undefined,
});

const workerCheckpointStateStreamDomain = 'worker-checkpoint-test';
const workerCheckpointStateBytes = Uint8Array.of(0x41);
const workerCheckpointChunkDigest = foundationHash512(
    'sealed-lattice/transport/chunk/v1',
    asciiItem(workerCheckpointStateStreamDomain),
    canonicalItem(0x04, unsigned32LittleEndian(0)),
    canonicalItem(
        0x04,
        unsigned32LittleEndian(workerCheckpointStateBytes.byteLength),
    ),
    variableBytesItem(workerCheckpointStateBytes),
);
const workerCheckpointStreamDescriptor = canonicalTuple(
    0x1800,
    unsigned64Item(BigInt(workerCheckpointStateBytes.byteLength)),
    canonicalItem(
        0x0e,
        concatenateBytes(
            unsigned16LittleEndian(0x06),
            unsigned32LittleEndian(1),
            workerCheckpointChunkDigest,
        ),
    ),
    hashItem(
        foundationHash512(
            'sealed-lattice/transport/full-object/v1',
            asciiItem(workerCheckpointStateStreamDomain),
            unsigned64Item(BigInt(workerCheckpointStateBytes.byteLength)),
            variableBytesItem(workerCheckpointStateBytes),
        ),
    ),
);

const createWorkerCheckpointBoundary = () =>
    Object.freeze({
        operationKind: 1,
        orderedRandomCursors: Object.freeze([]),
        orderedSourceDigests: Object.freeze([]),
        safeBoundaryOrdinal: 1,
        stateStreamDescriptorBytes: workerCheckpointStreamDescriptor.slice(),
        stateStreamDomain: workerCheckpointStateStreamDomain,
    });

const createExpectedWorkerCheckpointBoundary = () =>
    Object.freeze({
        operationKind: 1,
        orderedRandomCursors: Object.freeze([]),
        orderedSourceDigests: Object.freeze([]),
        safeBoundaryOrdinal: 1,
        stateStreamDomain: workerCheckpointStateStreamDomain,
    });

type SameRealmCustodyWorkerResponse = Readonly<{
    errorCode?: string;
    errorMessage?: string;
    messageKind: string;
    requestIdentifier?: number;
    result?: unknown;
}>;

class SameRealmCustodyWorkerScope {
    readonly #pendingResponses = new Map<
        number,
        Readonly<{
            reject(error: unknown): void;
            resolve(value: unknown): void;
        }>
    >();
    #listener: ((event: MessageEvent<unknown>) => void) | undefined;
    #nextRequestIdentifier = 1;
    public readonly terminalNotifications: SameRealmCustodyWorkerResponse[] =
        [];

    public addEventListener(
        type: 'message',
        listener: (event: MessageEvent<unknown>) => void,
    ): void {
        if (type !== 'message' || this.#listener !== undefined) {
            throw new Error(
                'The same-realm custody worker listener was installed more than once.',
            );
        }
        this.#listener = listener;
    }

    public removeEventListener(
        type: 'message',
        listener: (event: MessageEvent<unknown>) => void,
    ): void {
        if (type !== 'message') {
            throw new Error(
                'The same-realm custody worker removed an unknown listener kind.',
            );
        }
        if (this.#listener === listener) {
            this.#listener = undefined;
        }
    }

    public postMessage(message: unknown): void {
        const response = message as SameRealmCustodyWorkerResponse;
        if (response.requestIdentifier === undefined) {
            this.terminalNotifications.push(response);
            const terminalFailure = Object.assign(
                new Error('The same-realm custody worker retired.'),
                { code: response.errorCode },
            );
            for (const pending of this.#pendingResponses.values()) {
                pending.reject(terminalFailure);
            }
            this.#pendingResponses.clear();
            return;
        }
        const pending = this.#pendingResponses.get(response.requestIdentifier);
        if (pending === undefined) {
            throw new Error(
                'The same-realm custody worker returned an unknown request identifier.',
            );
        }
        this.#pendingResponses.delete(response.requestIdentifier);
        if (
            response.messageKind === 'browser-action-storage-custody-completed'
        ) {
            pending.resolve(response.result);
            return;
        }
        const failure = new Error(
            response.errorMessage ??
                `The same-realm custody worker command failed with ${response.errorCode ?? 'an unclassified error'}.`,
        ) as Error & { code?: string };
        failure.code = response.errorCode;
        pending.reject(failure);
    }

    public dispatchMalformedRequest(data: unknown = undefined): void {
        const listener = this.#listener;
        if (listener === undefined) {
            throw new Error('The same-realm custody worker is not listening.');
        }
        listener({ data } as MessageEvent<unknown>);
    }

    public send(command: string, input: unknown): Promise<unknown> {
        const listener = this.#listener;
        if (listener === undefined) {
            return Promise.reject(
                new Error('The same-realm custody worker is not listening.'),
            );
        }
        const requestIdentifier = this.#nextRequestIdentifier;
        this.#nextRequestIdentifier += 1;
        return new Promise((resolve, reject) => {
            this.#pendingResponses.set(requestIdentifier, {
                reject,
                resolve,
            });
            listener({
                data: {
                    command,
                    input,
                    messageKind: 'browser-action-storage-custody-request',
                    requestIdentifier,
                },
            } as MessageEvent<unknown>);
        });
    }
}

const createFoundationStateDurableBinding = (
    kernel: TranscriptCoreKernel,
): Readonly<{
    binding: VerifiedStateDurableBinding;
    session: StateVerifierSession;
    stateVector: ReturnType<typeof createStateVerifierTestVector>;
}> => {
    const stateVector = createStateVerifierTestVector();
    const opened = openStateVerifierSession({
        configuration: {
            actionContextHash: stateVector.actionContextHash,
            canonicalRosterBytes: stateVector.canonicalRosterBytes,
            ceremonyContextHash: stateVector.ceremonyContextHash,
            suiteIdentifier: stateVector.suiteIdentifier,
        },
        kernel,
    });
    if (!opened.isValid) {
        throw new Error(opened.refusalReason);
    }
    const reservationIntent = opened.value.verifyReservationIntent({
        canonicalReservationIntentCarrier:
            stateVector.reservation.canonicalIntentCarrier,
        capabilityKind: stateCapabilityKinds.targetRelease,
        expectedAuthorizationHash: stateVector.authorizationHash,
        subjectParticipantIdentity: stateVector.subjectParticipantIdentity,
    });
    if (!reservationIntent.isValid) {
        opened.value.cancel();
        throw new Error(reservationIntent.refusalReason);
    }
    const durableBinding = opened.value.durableBindingFor(
        reservationIntent.value,
    );
    if (!durableBinding.isValid) {
        opened.value.cancel();
        throw new Error(durableBinding.refusalReason);
    }
    return Object.freeze({
        binding: durableBinding.value,
        session: opened.value,
        stateVector,
    });
};

const openSameRealmCommonProofApplicationHost = async (input?: {
    additionalInitializationCommitGate?: Promise<void>;
    firstAdditionalInitializationWitnessCount?: number;
    decorateCommonProofCustody?: (
        custody: CommonProofBrowserCustody,
    ) => CommonProofBrowserCustody;
    failActionRandomnessCloseAttemptNumbers?: readonly number[];
    failFirstAdditionalActivationHeadComparison?: boolean;
    failFirstFoundationWitnessClose?: boolean;
    failFoundationWitnessCloseAttemptNumbers?: readonly number[];
    failFirstStateObjectRelease?: boolean;
    failVerifiedCapabilityReleaseAttempt?: number;
    onAdditionalInitializationCommitStarted?: () => void;
    proofBytes?: Uint8Array;
}): Promise<
    Readonly<{
        actionRandomnessHandleIdentifier: string;
        authenticatedFoundationHead(): Promise<BrowserFoundationFreshnessCoordinate>;
        activateFreshFoundationInitialization(batchIdentifier: string): Promise<
            Readonly<{
                actionRandomnessHandleIdentifier: string;
                orderedWitnessRoleHandleIdentifiers: readonly string[];
            }>
        >;
        close(): Promise<void>;
        commitAdditionalFoundationOperationInitialization(): Promise<string>;
        cleanupAttemptCounts(): Readonly<{
            actionRandomness: number;
            foundationWitness: number;
            stateObjectRelease: number;
        }>;
        fixture: Awaited<ReturnType<typeof createVerifiedApplicationFixture>>;
        installedHost: () => Promise<void>;
        kernel: TranscriptCoreKernel;
        ownedCustodyCloseCount(): number;
        retainAdditionalFoundationInitializationBatches(): Promise<void>;
        retainFoundationStateReservationIntent(): Promise<string>;
        workerScope: SameRealmCustodyWorkerScope;
        witnessRoleIdentifier: string;
    }>
> => {
    const fixture = await createVerifiedApplicationFixture({
        failVerifiedCapabilityReleaseAttempt:
            input?.failVerifiedCapabilityReleaseAttempt,
        predecessorFreshnessSequence: 0n,
        proofBytes: input?.proofBytes,
    });
    const kernel = await loadFreshTranscriptCoreKernel();
    registerCommonProofKernelContext(kernel, fixture.runtime);
    const workerKernel = createWasmBrowserActionStorageWorkerKernel({ kernel });
    const stateAuthority = createFoundationStateDurableBinding(kernel);
    let stateAuthoritySessionCancelled = false;
    const cancelStateAuthoritySession = (): void => {
        if (stateAuthoritySessionCancelled) {
            return;
        }
        stateAuthority.session.cancel();
        stateAuthoritySessionCancelled = true;
    };
    const foundationSigningKeyPairs =
        createCanonicalCarrierSigningKeyPairFixtures(
            foundationProfile.participantCount,
        );
    const witnessSigningSecretKey =
        foundationSigningKeyPairs[1]?.secretKey.slice();
    for (const keyPair of foundationSigningKeyPairs) {
        keyPair.secretKey.fill(0);
    }
    if (witnessSigningSecretKey === undefined) {
        throw new Error('The foundation fixture has no witness signing key.');
    }
    const binding: BrowserActionStorageRootBinding = Object.freeze({
        actionContextHash: stateAuthority.stateVector.actionContextHash.slice(),
        ceremonyContextHash:
            stateAuthority.stateVector.ceremonyContextHash.slice(),
        participantId:
            stateAuthority.stateVector.witnessParticipantIdentity.slice(),
        suiteId: stateAuthority.stateVector.suiteIdentifier.slice(),
    });
    const preparedRoot = await workerKernel.createAndStageDeviceWrappingState({
        binding,
    });
    await workerKernel.commitStagedActionStorageRoot();
    preparedRoot.storageRootCommitment.fill(0);
    preparedRoot.wrappedStorageRoot.fill(0);
    const stateCleanupActionRandomness =
        input?.failFirstStateObjectRelease === true
            ? await workerKernel.createAndSealActionRandomness({
                  recordVersion: 0n,
              })
            : undefined;
    stateCleanupActionRandomness?.canonicalEnvelope.fill(0);
    const releaseActionStateObject: (identifier: string) => Promise<void> =
        workerKernel.releaseActionStateObject.bind(workerKernel);
    let stateObjectReleaseAttemptCount = 0;
    if (input?.failFirstStateObjectRelease === true) {
        Object.defineProperty(workerKernel, 'releaseActionStateObject', {
            configurable: true,
            value: async (identifier: string): Promise<void> => {
                stateObjectReleaseAttemptCount += 1;
                if (stateObjectReleaseAttemptCount === 1) {
                    throw new Error('Injected fail-once state-object release.');
                }
                await releaseActionStateObject(identifier);
            },
        });
    }

    const storage = await openRuntimeTestStore({
        limits: foundationStorageTransactionLimits,
        namespace: 'same-realm-common-proof-application-test',
    });
    const checkpointStorage = await openRuntimeTestStore({
        namespace: 'same-realm-common-proof-checkpoint-test',
    });
    const repairHeadLogicalRecordKey =
        'test/same-realm-common-proof-capacity-head';
    const repairHeadWriteTransaction = await storage.store.beginTransaction({
        lifetimeMilliseconds: 5_000,
    });
    try {
        const repairHeadWriteLease =
            await repairHeadWriteTransaction.issueWriteLease({
                declaredByteLength: 1,
                logicalRecordKey: repairHeadLogicalRecordKey,
            });
        await repairHeadWriteLease.write(Uint8Array.of(1));
        await repairHeadWriteLease.seal(() => undefined);
        await repairHeadWriteTransaction.commit();
    } catch (error) {
        await repairHeadWriteTransaction.closeAfterFailure();
        throw error;
    }
    const repairHeadDeleteTransaction = await storage.store.beginTransaction({
        lifetimeMilliseconds: 5_000,
    });
    try {
        await repairHeadDeleteTransaction.stageDeletion(
            repairHeadLogicalRecordKey,
        );
        await repairHeadDeleteTransaction.commit();
    } catch (error) {
        await repairHeadDeleteTransaction.closeAfterFailure();
        throw error;
    }
    const baselineAuthenticatedHead =
        await storage.store.authenticateCurrentHead();
    const baselineFreshnessSequence =
        baselineAuthenticatedHead.namespaceSequence;
    const baselineAuthenticatedHeadDigest =
        baselineAuthenticatedHead.authenticatedHeadDigest.slice();
    baselineAuthenticatedHead.authenticatedHeadDigest.fill(0);
    baselineAuthenticatedHead.storageInstanceIdentity.fill(0);
    const encryptionKey = await generateRuntimeStorageEncryptionKey();
    let transferableCheckpointStore:
        | ReturnType<typeof openAuthenticatedCheckpointStore>
        | undefined;
    const baselineFoundationCoordinate =
        (): BrowserFoundationFreshnessCoordinate =>
            Object.freeze({
                authenticatedHeadDigest: new Uint8Array(hashByteLength).fill(
                    0x51,
                ),
                freshnessSequence: 0n,
                storageInstanceIdentity: new Uint8Array(hashByteLength).fill(
                    0x61,
                ),
            });
    let openedFoundationWitnessRoleCount = 0;
    let injectedAdditionalActivationHeadConflict = false;
    const coordinateForCurrentStore =
        async (): Promise<BrowserFoundationFreshnessCoordinate> => {
            const authenticatedHead =
                await storage.store.authenticateCurrentHead();
            const freshnessSequence =
                authenticatedHead.namespaceSequence - baselineFreshnessSequence;
            const authenticatedHeadDigest =
                authenticatedHead.authenticatedHeadDigest.slice();
            for (
                let digestByteIndex = 0;
                digestByteIndex < authenticatedHeadDigest.byteLength;
                digestByteIndex += 1
            ) {
                authenticatedHeadDigest[digestByteIndex] ^=
                    baselineAuthenticatedHeadDigest[digestByteIndex] ^ 0x51;
            }
            authenticatedHead.authenticatedHeadDigest.fill(0);
            authenticatedHead.storageInstanceIdentity.fill(0);
            if (
                input?.failFirstAdditionalActivationHeadComparison === true &&
                !injectedAdditionalActivationHeadConflict &&
                openedFoundationWitnessRoleCount >=
                    2 * (foundationProfile.participantCount - 1)
            ) {
                authenticatedHeadDigest[0] ^= 0xff;
                injectedAdditionalActivationHeadConflict = true;
            }
            return Object.freeze({
                authenticatedHeadDigest,
                freshnessSequence,
                storageInstanceIdentity: new Uint8Array(hashByteLength).fill(
                    0x61,
                ),
            });
        };
    const witnessRecords: WebLockFoundationWitnessRecord[] = Array.from(
        { length: 9 },
        (_unused, witnessIndex) =>
            Object.freeze({
                actionRandomnessCommitment: new Uint8Array(64).fill(0x21),
                authorizedEmptyPlaintext: Uint8Array.of(0),
                localRecordIdentifier: new Uint8Array(64).fill(
                    0x31 + witnessIndex,
                ),
                roleIndex: witnessIndex,
                stateKey: new Uint8Array(64).fill(0x41 + witnessIndex),
                subjectParticipantIdentity:
                    witnessIndex === 0
                        ? stateAuthority.stateVector.subjectParticipantIdentity.slice()
                        : new Uint8Array(64).fill(0x61 + witnessIndex),
                witnessParticipantIdentity: binding.participantId.slice(),
            }),
    );
    const copyWitnessRecord = (
        record: WebLockFoundationWitnessRecord,
    ): WebLockFoundationWitnessRecord =>
        Object.freeze({
            actionRandomnessCommitment:
                record.actionRandomnessCommitment.slice(),
            authorizedEmptyPlaintext: record.authorizedEmptyPlaintext.slice(),
            localRecordIdentifier: record.localRecordIdentifier.slice(),
            roleIndex: record.roleIndex,
            stateKey: record.stateKey.slice(),
            subjectParticipantIdentity:
                record.subjectParticipantIdentity.slice(),
            witnessParticipantIdentity:
                record.witnessParticipantIdentity.slice(),
        });
    const byteArraysEqual = (left: Uint8Array, right: Uint8Array): boolean =>
        left.byteLength === right.byteLength &&
        left.every((byte, byteIndex) => byte === right[byteIndex]);
    const witnessRecordsEqual = (
        left: WebLockFoundationWitnessRecord,
        right: WebLockFoundationWitnessRecord,
    ): boolean =>
        left.roleIndex === right.roleIndex &&
        byteArraysEqual(
            left.actionRandomnessCommitment,
            right.actionRandomnessCommitment,
        ) &&
        byteArraysEqual(
            left.authorizedEmptyPlaintext,
            right.authorizedEmptyPlaintext,
        ) &&
        byteArraysEqual(
            left.localRecordIdentifier,
            right.localRecordIdentifier,
        ) &&
        byteArraysEqual(left.stateKey, right.stateKey) &&
        byteArraysEqual(
            left.subjectParticipantIdentity,
            right.subjectParticipantIdentity,
        ) &&
        byteArraysEqual(
            left.witnessParticipantIdentity,
            right.witnessParticipantIdentity,
        );
    let committedInitializationCount = 0;
    const createCommittedInitialization =
        (): WebLockCommittedBrowserFoundationInitialization => {
            const initializationIndex = committedInitializationCount;
            committedInitializationCount += 1;
            const retainedActionRandomness =
                initializationIndex === 0
                    ? stateCleanupActionRandomness
                    : undefined;
            const actionRandomnessCommitment =
                retainedActionRandomness?.actionRandomnessCommitment.slice() ??
                new Uint8Array(64).fill(0x21 + initializationIndex);
            retainedActionRandomness?.actionRandomnessCommitment.fill(0);
            const orderedWitnessRecords =
                initializationIndex === 1 &&
                input?.firstAdditionalInitializationWitnessCount !== undefined
                    ? witnessRecords.slice(
                          0,
                          input.firstAdditionalInitializationWitnessCount,
                      )
                    : witnessRecords;
            return Object.freeze({
                actionRandomnessCommitment,
                actionRandomnessSessionIdentifier:
                    retainedActionRandomness?.actionRandomnessSessionIdentifier ??
                    (10 + (initializationIndex % 6)).toString(16).repeat(64),
                freshnessCoordinate: baselineFoundationCoordinate(),
                orderedWitnessRecords: Object.freeze(
                    orderedWitnessRecords.map(copyWitnessRecord),
                ),
            });
        };
    const failedActionRandomnessCloseAttempts = new Set(
        input?.failActionRandomnessCloseAttemptNumbers,
    );
    let actionRandomnessCloseAttemptCount = 0;
    let foundationWitnessCloseAttemptCount = 0;
    let failedFirstFoundationWitnessClose = false;
    const failedFoundationWitnessCloseAttempts = new Set(
        input?.failFoundationWitnessCloseAttemptNumbers,
    );
    let ownedCustodyCloseCount = 0;
    const custodyFacade = Object.freeze({
        closeActionRandomness: async (identifier: string) => {
            actionRandomnessCloseAttemptCount += 1;
            if (
                failedActionRandomnessCloseAttempts.delete(
                    actionRandomnessCloseAttemptCount,
                )
            ) {
                throw new Error(
                    `Injected action-randomness close failure ${String(actionRandomnessCloseAttemptCount)}.`,
                );
            }
            if (
                identifier ===
                stateCleanupActionRandomness?.actionRandomnessSessionIdentifier
            ) {
                await workerKernel.closeActionRandomness(identifier);
            }
        },
        copyBinding: () => ({
            actionContextHash: binding.actionContextHash.slice(),
            ceremonyContextHash: binding.ceremonyContextHash.slice(),
            participantId: binding.participantId.slice(),
            suiteId: binding.suiteId.slice(),
        }),
        closeActionStateVerifierSession: (identifier: string) =>
            workerKernel.closeActionStateVerifierSession(identifier),
        openActionStateVerifierSession: (
            sessionInput: Parameters<
                typeof workerKernel.openActionStateVerifierSession
            >[0],
        ) => workerKernel.openActionStateVerifierSession(sessionInput),
    }) as unknown as BrowserActionStorageCustody;
    const ownedCustody = Object.freeze({
        authenticateFoundationHead: coordinateForCurrentStore,
        close: async () => {
            ownedCustodyCloseCount += 1;
            await workerKernel.destroyActiveActionStorageRoot();
        },
        commitFreshFoundationInitialization: async () => {
            if (
                committedInitializationCount > 0 &&
                input?.additionalInitializationCommitGate !== undefined
            ) {
                input.onAdditionalInitializationCommitStarted?.();
                await input.additionalInitializationCommitGate;
            }
            return createCommittedInitialization();
        },
        custody: custodyFacade,
        openCheckpointStore: () => {
            transferableCheckpointStore ??= openAuthenticatedCheckpointStore({
                authorityContext: runtimeAuthorityContext({
                    actionContextHash: binding.actionContextHash,
                    ceremonyContextHash: binding.ceremonyContextHash,
                    ownerParticipantIdentity: binding.participantId,
                    suiteIdentifier: binding.suiteId,
                }),
                boundaryPolicy: commonProofCheckpointBoundaryPolicy,
                cryptoProvider,
                cursorKernel: kernel,
                encryptionKey,
                limits: commonProofCheckpointLimits,
                store: checkpointStorage.store,
            });
            return Promise.resolve(transferableCheckpointStore);
        },
        openCommonProofCustody: async (commonProofInput) => {
            const attemptLogicalRecordPrefix =
                deriveCommonProofAttemptLogicalRecordPrefix(commonProofInput);
            const capacityReservation =
                await storage.store.reserveExclusiveCapacity({
                    initialLogicalRecordKeyPrefixes: [
                        attemptLogicalRecordPrefix,
                        commonProofApplicationHandoffLogicalRecordKey,
                    ],
                    maximumAdditionalAuthenticatedRepairHeadPlaintextByteLength:
                        commonProofStorageCapacityProfile.maximumAdditionalAuthenticatedRepairHeadPlaintextByteLength,
                    maximumAdditionalOwnedRecordCount:
                        commonProofStorageCapacityProfile.maximumAdditionalOwnedRecordCount,
                    maximumAdditionalStoredValueByteLength:
                        commonProofStorageCapacityProfile.maximumAdditionalStoredValueByteLength,
                    maximumDeletionBatchRecordCount:
                        commonProofStorageCapacityProfile.maximumLeaseCountPerTransaction,
                });
            try {
                const commonProofCustody = openCommonProofBrowserCustody({
                    ...commonProofInput,
                    capacityReservation,
                    limits: {
                        maximumExternalMemoryByteLength: 268_435_456n,
                        maximumExternalMemoryObjectCount: 4_096,
                        maximumExternalMemoryRecordCount: 17_749,
                        transactionLifetimeMilliseconds: 10_000,
                    },
                    store: storage.store,
                    workerKernel,
                });
                return (
                    input?.decorateCommonProofCustody?.(commonProofCustody) ??
                    commonProofCustody
                );
            } catch (error) {
                await capacityReservation.release();
                throw error;
            }
        },
        openFoundationWitnessRole: (
            witnessRoleInput,
        ): Promise<WebLockOwnedFoundationWitnessRole> => {
            const expectedWitnessRecord =
                witnessRecords[witnessRoleInput.record.roleIndex];
            if (
                expectedWitnessRecord === undefined ||
                !witnessRecordsEqual(
                    witnessRoleInput.record,
                    expectedWitnessRecord,
                )
            ) {
                throw new Error(
                    'Foundation activation did not preserve the exact retained witness record.',
                );
            }
            const witnessRoleIndex = openedFoundationWitnessRoleCount;
            openedFoundationWitnessRoleCount += 1;
            const durableStateService = openDurableStateWitnessService({
                authorityContext: runtimeAuthorityContext({
                    actionContextHash: binding.actionContextHash,
                    ceremonyContextHash: binding.ceremonyContextHash,
                    ownerParticipantIdentity: binding.participantId,
                    suiteIdentifier: binding.suiteId,
                }),
                encryptionKey,
                limits: foundationWitnessServiceLimits,
                store: storage.store,
            });
            const exposedDurableStateService =
                input?.failFirstFoundationWitnessClose === true ||
                input?.failFoundationWitnessCloseAttemptNumbers !== undefined
                    ? Object.freeze({
                          ...durableStateService,
                          claimExclusiveOwner: () => {
                              const claimed =
                                  durableStateService.claimExclusiveOwner();
                              return Object.freeze({
                                  ...claimed,
                                  close: async () => {
                                      foundationWitnessCloseAttemptCount += 1;
                                      if (
                                          failedFoundationWitnessCloseAttempts.delete(
                                              foundationWitnessCloseAttemptCount,
                                          ) ||
                                          (witnessRoleIndex === 0 &&
                                              !failedFirstFoundationWitnessClose)
                                      ) {
                                          failedFirstFoundationWitnessClose = true;
                                          throw new Error(
                                              'Injected fail-once foundation witness close.',
                                          );
                                      }
                                      await claimed.close();
                                  },
                              });
                          },
                      })
                    : durableStateService;
            return Promise.resolve(
                Object.freeze({
                    durableStateService: exposedDurableStateService,
                }),
            );
        },
        openRecoveredFoundationInitialization: () =>
            Promise.reject(
                new Error(
                    'The common-proof application test does not recover initialization.',
                ),
            ),
        openRootAndAuthenticatedStore: () =>
            Promise.reject(
                new Error(
                    'The common-proof application test activates the root directly.',
                ),
            ),
        openRuntimeRecordProtection: () =>
            Promise.reject(
                new Error(
                    'The common-proof application test does not open record protection.',
                ),
            ),
        retire: () => Promise.resolve(),
        state: () => 'open' as const,
    }) as WebLockOwnedBrowserActionStorageCustody;
    const workerScope = new SameRealmCustodyWorkerScope();
    const uninstall = installBrowserActionStorageCustodyWorkerHost({
        foundationWitnessRuntime: {
            durableStateLimits: foundationWitnessServiceLimits,
            openVerifiedStateDurableBinding: () =>
                Promise.resolve({
                    isValid: true,
                    value: stateAuthority.binding,
                }),
            openWitnessCryptography: () => ({
                stateObjectSignatureOperation: Object.freeze({
                    signStateObjectMessage: (signatureMessageHash) =>
                        signCanonicalCarrierFixtureMessage(
                            signatureMessageHash,
                            witnessSigningSecretKey,
                        ),
                }),
            }),
        },
        checkpointStore: {
            boundaryPolicy: commonProofCheckpointBoundaryPolicy,
            cursorKernel: kernel,
            limits: commonProofCheckpointLimits,
        },
        cryptoProvider,
        openOwnedCustody: () => Promise.resolve(ownedCustody),
        workerKernel,
        workerScope,
    });
    const workerConfiguration: BrowserActionStorageCustodyWorkerConfiguration =
        Object.freeze({
            acquisitionDeadlineEpochMilliseconds: undefined,
            binding,
            databaseName: 'same-realm-common-proof-application-test',
            knownStorageRootCommitment: undefined,
            limits: foundationStorageTransactionLimits,
            namespace: 'same-realm-proof',
            runtimeBuildManifestHash: new Uint8Array(64).fill(0x73),
        });
    await workerScope.send('open-custody', workerConfiguration);
    const initializationInput: BrowserFoundationInitializationInput =
        Object.freeze({
            actionRandomnessRecordContext: { recordVersion: 0n },
            canonicalRosterBytes:
                stateAuthority.stateVector.canonicalRosterBytes.slice(),
            orderedWitnessBindings: Object.freeze(
                witnessRecords.map((record) => ({
                    subjectParticipantIdentity:
                        record.subjectParticipantIdentity.slice(),
                    witnessParticipantIdentity:
                        record.witnessParticipantIdentity.slice(),
                })),
            ),
            runtimeBuildManifestHash: new Uint8Array(64).fill(0x73),
        });
    const committed = (await workerScope.send(
        'commit-foundation-operation-initialization',
        initializationInput,
    )) as Readonly<{ batchIdentifier: string }>;
    const activated = (await workerScope.send(
        'activate-fresh-foundation-initialization',
        committed.batchIdentifier,
    )) as Readonly<{
        actionRandomnessHandleIdentifier: string;
        orderedWitnessRoleHandleIdentifiers: readonly string[];
    }>;
    const witnessRoleIdentifier =
        activated.orderedWitnessRoleHandleIdentifiers[0];
    if (witnessRoleIdentifier === undefined) {
        await uninstall();
        cancelStateAuthoritySession();
        throw new Error('The same-realm custody host opened no witness role.');
    }
    let closed = false;
    const close = async (): Promise<void> => {
        if (closed) {
            return;
        }
        await uninstall();
        stateAuthority.session.cancel();
        witnessSigningSecretKey.fill(0);
        closed = true;
    };
    const retainAdditionalFoundationInitializationBatches = async () => {
        await commitAdditionalFoundationOperationInitialization();
        await workerScope.send('commit-fresh-foundation-initialization', {
            actionRandomnessRecordContext:
                initializationInput.actionRandomnessRecordContext,
            orderedWitnessBindings: initializationInput.orderedWitnessBindings,
            runtimeBuildManifestHash:
                initializationInput.runtimeBuildManifestHash,
        });
    };
    const commitAdditionalFoundationOperationInitialization =
        async (): Promise<string> => {
            const additionalCommitted = (await workerScope.send(
                'commit-foundation-operation-initialization',
                initializationInput,
            )) as Readonly<{ batchIdentifier: string }>;
            return additionalCommitted.batchIdentifier;
        };
    const activateFreshFoundationInitialization = async (
        batchIdentifier: string,
    ): Promise<
        Readonly<{
            actionRandomnessHandleIdentifier: string;
            orderedWitnessRoleHandleIdentifiers: readonly string[];
        }>
    > =>
        (await workerScope.send(
            'activate-fresh-foundation-initialization',
            batchIdentifier,
        )) as Readonly<{
            actionRandomnessHandleIdentifier: string;
            orderedWitnessRoleHandleIdentifiers: readonly string[];
        }>;
    const retainFoundationStateReservationIntent =
        async (): Promise<string> => {
            cancelStateAuthoritySession();
            const openedStateVerifierSession = (await workerScope.send(
                'open-state-verifier-session',
                {
                    canonicalRosterBytes:
                        stateAuthority.stateVector.canonicalRosterBytes,
                },
            )) as
                | Readonly<{ isValid: false; refusalReason: string }>
                | Readonly<{ isValid: true; value: string }>;
            if (!openedStateVerifierSession.isValid) {
                throw new Error(openedStateVerifierSession.refusalReason);
            }
            try {
                const produced = (await workerScope.send(
                    'produce-foundation-action-randomness-reservation-intent',
                    {
                        actionRandomnessHandleIdentifier:
                            activated.actionRandomnessHandleIdentifier,
                        stateVerifierSessionIdentifier:
                            openedStateVerifierSession.value,
                    },
                )) as
                    | Readonly<{ isValid: false; refusalReason: string }>
                    | Readonly<{
                          isValid: true;
                          value: Readonly<{ stateIntentIdentifier: string }>;
                      }>;
                if (!produced.isValid) {
                    throw new Error(produced.refusalReason);
                }
                return produced.value.stateIntentIdentifier;
            } finally {
                await workerScope.send(
                    'close-state-verifier-session',
                    openedStateVerifierSession.value,
                );
            }
        };
    return Object.freeze({
        actionRandomnessHandleIdentifier:
            activated.actionRandomnessHandleIdentifier,
        activateFreshFoundationInitialization,
        authenticatedFoundationHead: coordinateForCurrentStore,
        close,
        commitAdditionalFoundationOperationInitialization,
        cleanupAttemptCounts: () =>
            Object.freeze({
                actionRandomness: actionRandomnessCloseAttemptCount,
                foundationWitness: foundationWitnessCloseAttemptCount,
                stateObjectRelease: stateObjectReleaseAttemptCount,
            }),
        fixture,
        installedHost: uninstall,
        kernel,
        ownedCustodyCloseCount: () => ownedCustodyCloseCount,
        retainAdditionalFoundationInitializationBatches,
        retainFoundationStateReservationIntent,
        workerScope,
        witnessRoleIdentifier,
    });
};

const createInstalledCommonProofGenerationFixture = (
    checkpointCursorBytes: Uint8Array<ArrayBuffer>,
    options: Readonly<{
        failFirstGenerationFamilyAdapterDiscard?: boolean;
        resumeCheckpointStateByteLength?: number;
    }> = {},
): Readonly<{
    binding: Uint8Array<ArrayBuffer>;
    checkpointStateBytes: Uint8Array<ArrayBuffer>;
    freshRuntime: TranscriptCoreKernelCommandRuntime;
    observations: {
        acknowledgedCheckpointCount: number;
        cancelledOperationReleaseCount: number;
        discardedGenerationFamilyAdapterCount: number;
        freshStorageResponseCount: number;
        generatedCapabilityReleaseCount: number;
        outputReadbackCount: number;
        prefixReplayResponseCount: number;
    };
    outputBytes: Uint8Array<ArrayBuffer>;
    resumeFamilyPreparationCount(): number;
    resumeRuntime: TranscriptCoreKernelCommandRuntime;
    verificationBinding: Uint8Array<ArrayBuffer>;
}> => {
    const binding = runtimeBinding(0x5b);
    const objectBytes = Uint8Array.from([4, 2, 1, 7, 9, 3, 8, 5]);
    const createStorageRequest = encodeRequest({
        maximumPayloadByteLength: 1n,
        operations: [
            {
                kind: 1,
                objectOrdinal: 12,
                payloadByteLength: BigInt(objectBytes.byteLength),
                position: 0n,
                protection: 2,
            },
        ],
        requestSequence: 1n,
        runtimeBindingHash: binding,
    });
    const appendStorageRequest = encodeRequest({
        maximumPayloadByteLength: BigInt(objectBytes.byteLength),
        operations: [
            {
                kind: 2,
                objectOrdinal: 12,
                payload: objectBytes,
                payloadByteLength: BigInt(objectBytes.byteLength),
                position: 0n,
                protection: 0,
            },
        ],
        requestSequence: 2n,
        runtimeBindingHash: binding,
    });
    const sealStorageRequest = encodeRequest({
        maximumPayloadByteLength: 1n,
        operations: [
            {
                kind: 3,
                objectOrdinal: 12,
                payloadByteLength: 0n,
                position: 0n,
                protection: 0,
            },
        ],
        requestSequence: 3n,
        runtimeBindingHash: binding,
    });
    const readStorageRequest = encodeRequest({
        maximumPayloadByteLength: BigInt(objectBytes.byteLength),
        operations: [
            {
                kind: 4,
                objectOrdinal: 12,
                payloadByteLength: BigInt(objectBytes.byteLength),
                position: 0n,
                protection: 0,
            },
        ],
        requestSequence: 4n,
        runtimeBindingHash: binding,
    });
    const freshStorageRequests = Object.freeze([
        createStorageRequest,
        appendStorageRequest,
        sealStorageRequest,
        readStorageRequest,
    ]);
    const checkpointStateBytes = new Uint8Array(37).fill(0x91);
    const stableAttemptBindingHash = new Uint8Array(hashByteLength).fill(0x62);
    const outputBytes = Uint8Array.from([8, 6, 7, 5, 3, 0, 9]);
    const observations = {
        acknowledgedCheckpointCount: 0,
        cancelledOperationReleaseCount: 0,
        discardedGenerationFamilyAdapterCount: 0,
        freshStorageResponseCount: 0,
        generatedCapabilityReleaseCount: 0,
        outputReadbackCount: 0,
        prefixReplayResponseCount: 0,
    };
    let freshPhase:
        | 'storage'
        | 'checkpoint'
        | 'awaiting-cancellation'
        | 'cancelled' = 'storage';
    let cancellationRequested = false;
    let freshStorageRequestIndex = 0;
    let generationFamilyAdapterDiscardFailed = false;
    const discardGenerationFamilyAdapter = (): number => {
        observations.discardedGenerationFamilyAdapterCount += 1;
        if (
            options.failFirstGenerationFamilyAdapterDiscard === true &&
            !generationFamilyAdapterDiscardFailed
        ) {
            generationFamilyAdapterDiscardFailed = true;
            return 0x0001_0001;
        }
        return 0;
    };
    const freshRuntime = createMockKernelRuntime((memory) => ({
        sealed_lattice_common_proof_describe_generation_family_adapter: (
            adapterHandle,
            runtimeBindingHashOutputPointer,
            verificationBindingHashOutputPointer,
            proofAttemptLineageIdentifierOutputPointer,
            statusPointer,
        ) => {
            expect([101, 103]).toContain(adapterHandle);
            memoryBytes(
                memory,
                runtimeBindingHashOutputPointer,
                hashByteLength,
            ).set(binding);
            memoryBytes(
                memory,
                verificationBindingHashOutputPointer,
                hashByteLength,
            ).set(installedCommonProofVerificationBindingHash);
            memoryBytes(
                memory,
                proofAttemptLineageIdentifierOutputPointer,
                installedProofAttemptLineageIdentifier.byteLength,
            ).set(installedProofAttemptLineageIdentifier);
            writeUnsigned32(memory, statusPointer, 0);
            return 0;
        },
        sealed_lattice_common_proof_prepare_generation_family_adapter: (
            adapterHandle,
            checkpointPointer,
            checkpointByteLength,
            statusPointer,
        ) => {
            expect([101, 103]).toContain(adapterHandle);
            expect(checkpointPointer).toBe(0);
            expect(checkpointByteLength).toBe(0);
            writeUnsigned32(memory, statusPointer, 0);
            return adapterHandle === 101 ? 201 : 203;
        },
        sealed_lattice_common_proof_discard_generation_family_adapter: (
            adapterHandle,
        ) => {
            expect([101, 103]).toContain(adapterHandle);
            return discardGenerationFamilyAdapter();
        },
        sealed_lattice_common_proof_discard_prepared_generation: (
            preparedGenerationHandle,
        ) => {
            if (preparedGenerationHandle === 201) {
                return 0x0001_0001;
            }
            expect(preparedGenerationHandle).toBe(203);
            throw new Error(
                'The installed family-adapter flow must not discard an unstarted prepared operation.',
            );
        },
        sealed_lattice_common_proof_begin_generation: (
            preparedGenerationHandle,
            statusPointer,
        ) => {
            expect(preparedGenerationHandle).toBe(201);
            writeUnsigned32(memory, statusPointer, 0);
            return 301;
        },
        sealed_lattice_common_proof_generation_poll: (
            operationHandle,
            pollKindPointer,
            primaryValuePointer,
            secondaryValuePointer,
        ) => {
            expect(operationHandle).toBe(301);
            if (freshPhase === 'storage') {
                const currentStorageRequest =
                    freshStorageRequests[freshStorageRequestIndex];
                if (currentStorageRequest === undefined) {
                    throw new Error(
                        'The fresh generation fixture exhausted its storage requests.',
                    );
                }
                return writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    2,
                    currentStorageRequest.byteLength,
                    noSecondPollValue,
                );
            }
            if (freshPhase === 'checkpoint') {
                return writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    1,
                    6,
                    1,
                );
            }
            expect(freshPhase).toBe('awaiting-cancellation');
            expect(cancellationRequested).toBe(true);
            freshPhase = 'cancelled';
            return writeGenerationPoll(
                memory,
                pollKindPointer,
                primaryValuePointer,
                secondaryValuePointer,
                6,
                0,
                noSecondPollValue,
            );
        },
        sealed_lattice_common_proof_generation_copy_storage_request: (
            operationHandle,
            outputPointer,
            outputByteLength,
        ) => {
            expect(operationHandle).toBe(301);
            const currentStorageRequest =
                freshStorageRequests[freshStorageRequestIndex];
            if (currentStorageRequest === undefined) {
                throw new Error(
                    'The fresh generation fixture exhausted its storage requests.',
                );
            }
            expect(outputByteLength).toBe(currentStorageRequest.byteLength);
            memoryBytes(memory, outputPointer, outputByteLength).set(
                currentStorageRequest,
            );
            return 0;
        },
        sealed_lattice_common_proof_generation_supply_storage_response: (
            operationHandle,
            _responsePointer,
            responseByteLength,
        ) => {
            expect(operationHandle).toBe(301);
            expect(freshPhase).toBe('storage');
            expect(responseByteLength).toBeGreaterThan(0);
            observations.freshStorageResponseCount += 1;
            freshStorageRequestIndex += 1;
            if (freshStorageRequestIndex === freshStorageRequests.length) {
                freshPhase = 'checkpoint';
            }
            return 0;
        },
        sealed_lattice_common_proof_generation_checkpoint_state_byte_length:
            () => checkpointStateBytes.byteLength,
        sealed_lattice_common_proof_generation_describe_checkpoint: (
            operationHandle,
            safeBoundaryOrdinalPointer,
            stateByteLengthPointer,
            cursorCountPointer,
        ) => {
            expect(operationHandle).toBe(301);
            expect(freshPhase).toBe('checkpoint');
            writeUnsigned32(memory, safeBoundaryOrdinalPointer, 6);
            writeUnsigned32(
                memory,
                stateByteLengthPointer,
                checkpointStateBytes.byteLength,
            );
            writeUnsigned32(memory, cursorCountPointer, 1);
            return 0;
        },
        sealed_lattice_common_proof_generation_copy_checkpoint_state: (
            operationHandle,
            outputPointer,
            outputByteLength,
        ) => {
            expect(operationHandle).toBe(301);
            expect(outputByteLength).toBe(checkpointStateBytes.byteLength);
            memoryBytes(memory, outputPointer, outputByteLength).set(
                checkpointStateBytes,
            );
            return 0;
        },
        sealed_lattice_common_proof_generation_checkpoint_cursor_byte_length: (
            operationHandle,
            cursorIndex,
            statusPointer,
        ) => {
            expect(operationHandle).toBe(301);
            expect(cursorIndex).toBe(0);
            writeUnsigned32(memory, statusPointer, 0);
            return checkpointCursorBytes.byteLength;
        },
        sealed_lattice_common_proof_generation_copy_checkpoint_cursor: (
            operationHandle,
            cursorIndex,
            outputPointer,
            outputByteLength,
        ) => {
            expect(operationHandle).toBe(301);
            expect(cursorIndex).toBe(0);
            expect(outputByteLength).toBe(checkpointCursorBytes.byteLength);
            memoryBytes(memory, outputPointer, outputByteLength).set(
                checkpointCursorBytes,
            );
            return 0;
        },
        sealed_lattice_common_proof_generation_copy_checkpoint_stable_attempt_binding_hash:
            (operationHandle, outputPointer, outputByteLength) => {
                expect(operationHandle).toBe(301);
                expect(outputByteLength).toBe(hashByteLength);
                memoryBytes(memory, outputPointer, outputByteLength).set(
                    stableAttemptBindingHash,
                );
                return 0;
            },
        sealed_lattice_common_proof_generation_acknowledge_checkpoint: (
            operationHandle,
        ) => {
            expect(operationHandle).toBe(301);
            expect(freshPhase).toBe('checkpoint');
            observations.acknowledgedCheckpointCount += 1;
            freshPhase = 'awaiting-cancellation';
            return 0;
        },
        sealed_lattice_common_proof_generation_request_cancellation: (
            operationHandle,
        ) => {
            expect(operationHandle).toBe(301);
            expect(freshPhase).toBe('awaiting-cancellation');
            cancellationRequested = true;
            return 0;
        },
        sealed_lattice_common_proof_generation_release_cancelled: (
            operationHandle,
        ) => {
            expect(operationHandle).toBe(301);
            expect(freshPhase).toBe('cancelled');
            observations.cancelledOperationReleaseCount += 1;
            return 0;
        },
        sealed_lattice_common_proof_generation_retire_failed: (
            operationHandle,
        ) => {
            expect(operationHandle).toBe(301);
            return 0;
        },
    }));

    let resumePhase:
        | 'replay'
        | 'resume-complete'
        | 'output'
        | 'readback'
        | 'complete'
        | 'finished' = 'replay';
    let resumeStorageRequestIndex = 0;
    let resumeFamilyPreparationCount = 0;
    const resumeRuntime = createMockKernelRuntime((memory) => ({
        sealed_lattice_common_proof_describe_generation_family_adapter: (
            adapterHandle,
            runtimeBindingHashOutputPointer,
            verificationBindingHashOutputPointer,
            proofAttemptLineageIdentifierOutputPointer,
            statusPointer,
        ) => {
            expect(adapterHandle).toBe(102);
            memoryBytes(
                memory,
                runtimeBindingHashOutputPointer,
                hashByteLength,
            ).set(binding);
            memoryBytes(
                memory,
                verificationBindingHashOutputPointer,
                hashByteLength,
            ).set(installedCommonProofVerificationBindingHash);
            memoryBytes(
                memory,
                proofAttemptLineageIdentifierOutputPointer,
                installedProofAttemptLineageIdentifier.byteLength,
            ).set(installedProofAttemptLineageIdentifier);
            writeUnsigned32(memory, statusPointer, 0);
            return 0;
        },
        sealed_lattice_common_proof_prepare_generation_family_adapter: (
            adapterHandle,
            checkpointPointer,
            checkpointByteLength,
            statusPointer,
        ) => {
            expect(adapterHandle).toBe(102);
            resumeFamilyPreparationCount += 1;
            expect([
                ...memoryBytes(memory, checkpointPointer, checkpointByteLength),
            ]).toEqual([...checkpointStateBytes]);
            writeUnsigned32(memory, statusPointer, 0);
            return 202;
        },
        sealed_lattice_common_proof_discard_generation_family_adapter: (
            adapterHandle,
        ) => {
            expect(adapterHandle).toBe(102);
            return discardGenerationFamilyAdapter();
        },
        sealed_lattice_common_proof_generation_checkpoint_state_byte_length:
            () =>
                options.resumeCheckpointStateByteLength ??
                checkpointStateBytes.byteLength,
        sealed_lattice_common_proof_resume_generation: (
            preparedGenerationHandle,
            checkpointPointer,
            checkpointByteLength,
            statusPointer,
        ) => {
            expect(preparedGenerationHandle).toBe(202);
            expect([
                ...memoryBytes(memory, checkpointPointer, checkpointByteLength),
            ]).toEqual([...checkpointStateBytes]);
            writeUnsigned32(memory, statusPointer, 0);
            return 302;
        },
        sealed_lattice_common_proof_generation_poll: (
            operationHandle,
            pollKindPointer,
            primaryValuePointer,
            secondaryValuePointer,
        ) => {
            expect(operationHandle).toBe(302);
            if (resumePhase === 'replay') {
                const currentStorageRequest =
                    freshStorageRequests[resumeStorageRequestIndex];
                if (currentStorageRequest === undefined) {
                    throw new Error(
                        'The resumed generation fixture exhausted its replay requests.',
                    );
                }
                return writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    2,
                    currentStorageRequest.byteLength,
                    noSecondPollValue,
                );
            }
            if (resumePhase === 'resume-complete') {
                resumePhase = 'output';
                return writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    7,
                    6,
                    noSecondPollValue,
                );
            }
            if (resumePhase === 'output') {
                return writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    3,
                    0,
                    outputBytes.byteLength,
                );
            }
            if (resumePhase === 'readback') {
                return writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    4,
                    0,
                    noSecondPollValue,
                );
            }
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
        sealed_lattice_common_proof_generation_copy_storage_request: (
            operationHandle,
            outputPointer,
            outputByteLength,
        ) => {
            expect(operationHandle).toBe(302);
            const currentStorageRequest =
                freshStorageRequests[resumeStorageRequestIndex];
            if (currentStorageRequest === undefined) {
                throw new Error(
                    'The resumed generation fixture exhausted its replay requests.',
                );
            }
            expect(outputByteLength).toBe(currentStorageRequest.byteLength);
            memoryBytes(memory, outputPointer, outputByteLength).set(
                currentStorageRequest,
            );
            return 0;
        },
        sealed_lattice_common_proof_generation_supply_storage_response: (
            operationHandle,
            _responsePointer,
            responseByteLength,
        ) => {
            expect(operationHandle).toBe(302);
            expect(resumePhase).toBe('replay');
            expect(responseByteLength).toBeGreaterThan(0);
            observations.prefixReplayResponseCount += 1;
            resumeStorageRequestIndex += 1;
            if (resumeStorageRequestIndex === freshStorageRequests.length) {
                resumePhase = 'resume-complete';
            }
            return 0;
        },
        sealed_lattice_common_proof_generation_copy_output_chunk: (
            operationHandle,
            chunkIndex,
            outputPointer,
            outputByteLength,
        ) => {
            expect(operationHandle).toBe(302);
            expect(chunkIndex).toBe(0);
            expect(outputByteLength).toBe(outputBytes.byteLength);
            memoryBytes(memory, outputPointer, outputByteLength).set(
                outputBytes,
            );
            return 0;
        },
        sealed_lattice_common_proof_generation_acknowledge_output_chunk: (
            operationHandle,
            chunkIndex,
        ) => {
            expect(operationHandle).toBe(302);
            expect(chunkIndex).toBe(0);
            expect(resumePhase).toBe('output');
            resumePhase = 'readback';
            return 0;
        },
        sealed_lattice_common_proof_generation_confirm_output_readback: (
            operationHandle,
            chunkIndex,
            readbackPointer,
            readbackByteLength,
        ) => {
            expect(operationHandle).toBe(302);
            expect(chunkIndex).toBe(0);
            expect([
                ...memoryBytes(memory, readbackPointer, readbackByteLength),
            ]).toEqual([...outputBytes]);
            observations.outputReadbackCount += 1;
            resumePhase = 'complete';
            return 0;
        },
        sealed_lattice_common_proof_generation_finish: (
            operationHandle,
            statusPointer,
        ) => {
            expect(operationHandle).toBe(302);
            expect(resumePhase).toBe('complete');
            writeUnsigned32(memory, statusPointer, 0);
            resumePhase = 'finished';
            return 402;
        },
        sealed_lattice_common_proof_release_generated_proof: (
            capabilityHandle,
        ) => {
            expect(capabilityHandle).toBe(402);
            expect(resumePhase).toBe('finished');
            observations.generatedCapabilityReleaseCount += 1;
            return 0;
        },
        sealed_lattice_common_proof_generation_retire_failed: (
            operationHandle,
        ) => {
            expect(operationHandle).toBe(302);
            return 0;
        },
    }));

    return Object.freeze({
        binding,
        checkpointStateBytes,
        freshRuntime,
        observations,
        outputBytes,
        resumeFamilyPreparationCount: () => resumeFamilyPreparationCount,
        resumeRuntime,
        verificationBinding:
            installedCommonProofVerificationBindingHash.slice(),
    });
};

describe('common-proof worker runtime', () => {
    it('decodes exact single-operation Rust storage transactions', () => {
        const binding = runtimeBinding(0x31);
        const appendBytes = Uint8Array.from([9, 8, 7, 6]);
        const request = encodeRequest({
            maximumPayloadByteLength: 4n,
            operations: [
                {
                    kind: 2,
                    objectOrdinal: 7,
                    payload: appendBytes,
                    payloadByteLength: 4n,
                    position: 0n,
                    protection: 0,
                },
            ],
            requestSequence: 1n,
            runtimeBindingHash: binding,
        });
        const decoded = decodeCommonProofExternalMemoryRequest(request);
        expect(decoded.requestSequence).toBe(1n);
        expect(decoded.maximumPayloadByteLength).toBe(4n);
        expect(decoded.operations).toHaveLength(1);
        const append = decoded.operations[0];
        expect(append?.operationKind).toBe('append');
        if (append?.operationKind !== 'append') {
            throw new Error('The append operation was not decoded.');
        }
        expect([...append.bytes]).toEqual([...appendBytes]);
        expect(append.bytes.buffer).not.toBe(request.buffer);

        const readRequest = decodeCommonProofExternalMemoryRequest(
            fourByteReadRequest(binding, 2n),
        );
        const transferredRead = Uint8Array.from([9, 8, 7, 6]);
        const response = encodeCommonProofExternalMemoryResponse(readRequest, [
            {
                bytes: transferredRead,
                objectOrdinal: 7,
                offset: 3n,
                operationIndex: 0,
            },
        ]);
        expect([...transferredRead]).toEqual([0, 0, 0, 0]);
        const responseView = new DataView(response.buffer);
        expect(responseView.getUint16(0, true)).toBe(1);
        expect(responseView.getUint16(2, true)).toBe(2);
        expect(responseView.getBigUint64(4, true)).toBe(2n);
        expect(responseView.getUint32(76, true)).toBe(1);
        expect(response.byteLength).toBe(80 + 88 + 4);
    });

    it('rejects truncation, trailing bytes, wrong digests, and noncanonical operation order', () => {
        const binding = runtimeBinding(0x32);
        const request = fourByteReadRequest(binding, 1n);
        expect(() =>
            decodeCommonProofExternalMemoryRequest(request.slice(0, -1)),
        ).toThrow(CommonProofWorkerRuntimeError);

        const trailing = new Uint8Array(request.byteLength + 1);
        trailing.set(request);
        expect(() => decodeCommonProofExternalMemoryRequest(trailing)).toThrow(
            CommonProofWorkerRuntimeError,
        );

        const wrongDigest = request.slice();
        wrongDigest[requestDigestOffset] ^= 1;
        expect(() =>
            decodeCommonProofExternalMemoryRequest(wrongDigest),
        ).toThrowError(expect.objectContaining({ code: 'WrongRequestDigest' }));

        const reordered = encodeRequest({
            maximumPayloadByteLength: 4n,
            operations: [
                {
                    encodedOrdinal: 1,
                    kind: 4,
                    objectOrdinal: 7,
                    payloadByteLength: 4n,
                    position: 3n,
                    protection: 0,
                },
            ],
            requestSequence: 1n,
            runtimeBindingHash: binding,
        });
        expect(() =>
            decodeCommonProofExternalMemoryRequest(reordered),
        ).toThrowError(expect.objectContaining({ code: 'MalformedRequest' }));

        const mixedRequest = encodeRequest({
            maximumPayloadByteLength: 1n,
            operations: [
                {
                    kind: 1,
                    objectOrdinal: 3,
                    payloadByteLength: 1n,
                    position: 0n,
                    protection: 1,
                },
                {
                    kind: 3,
                    objectOrdinal: 3,
                    payloadByteLength: 0n,
                    position: 0n,
                    protection: 0,
                },
            ],
            requestSequence: 2n,
            runtimeBindingHash: binding,
        });
        expect(() =>
            decodeCommonProofExternalMemoryRequest(mixedRequest),
        ).toThrowError(expect.objectContaining({ code: 'MalformedRequest' }));

        const deleteRequest = encodeRequest({
            maximumPayloadByteLength: 1n,
            operations: [
                {
                    kind: 5,
                    objectOrdinal: 3,
                    payloadByteLength: 0n,
                    position: 0n,
                    protection: 0,
                },
                {
                    kind: 5,
                    objectOrdinal: 4,
                    payloadByteLength: 0n,
                    position: 0n,
                    protection: 0,
                },
            ],
            requestSequence: 3n,
            runtimeBindingHash: binding,
        });
        expect(
            decodeCommonProofExternalMemoryRequest(deleteRequest).operations,
        ).toHaveLength(2);
    });

    it('rejects substituted single-read storage results', () => {
        const binding = runtimeBinding(0x35);
        const request = encodeRequest({
            maximumPayloadByteLength: 4n,
            operations: [
                {
                    kind: 4,
                    objectOrdinal: 4,
                    payloadByteLength: 4n,
                    position: 10n,
                    protection: 0,
                },
            ],
            requestSequence: 1n,
            runtimeBindingHash: binding,
        });
        const substitutedResults = [readResult(0, 4, 11n, [4, 4, 4, 4])];
        const decodedRequest = decodeCommonProofExternalMemoryRequest(request);
        expect(() =>
            encodeCommonProofExternalMemoryResponse(
                decodedRequest,
                substitutedResults,
            ),
        ).toThrowError(expect.objectContaining({ code: 'WrongStorageResult' }));
        expect(
            encodeCommonProofExternalMemoryResponse(decodedRequest, [
                readResult(0, 4, 10n, [4, 4, 4, 4]),
            ]),
        ).toBeInstanceOf(Uint8Array);
    });

    it('owns the exact request view independently of its backing buffer', () => {
        const binding = runtimeBinding(0x36);
        const request = fourByteReadRequest(binding, 1n);
        const oversizedBackingBuffer = new Uint8Array(
            request.byteLength + 2_000_000,
        );
        const requestOffset = 17;
        oversizedBackingBuffer.set(request, requestOffset);
        const exactRequestView = oversizedBackingBuffer.subarray(
            requestOffset,
            requestOffset + request.byteLength,
        );
        const decodedView =
            decodeCommonProofExternalMemoryRequest(exactRequestView);
        exactRequestView.fill(0);
        expect(decodedView.requestSequence).toBe(1n);
        expect([...decodedView.runtimeBindingHash]).toEqual([...binding]);
        expect(decodedView.operations).toHaveLength(1);

        const appendPayload = new Uint8Array(49_152).fill(0x5a);
        const maximumRequest = encodeRequest({
            maximumPayloadByteLength: 49_152n,
            operations: [
                {
                    kind: 2,
                    objectOrdinal: 9,
                    payload: appendPayload,
                    payloadByteLength: 49_152n,
                    position: 0n,
                    protection: 0,
                },
            ],
            requestSequence: 1n,
            runtimeBindingHash: runtimeBinding(0x37),
        });
        const decoded = decodeCommonProofExternalMemoryRequest(maximumRequest);
        const appendOperation = decoded.operations[0];
        expect(appendOperation?.operationKind).toBe('append');
        if (appendOperation?.operationKind !== 'append') {
            throw new Error('The maximum append operation was not decoded.');
        }
        expect(appendOperation.bytes.byteLength).toBe(49_152);
        expect(appendOperation.bytes.buffer).not.toBe(maximumRequest.buffer);
        maximumRequest.fill(0);
        expect(appendOperation.bytes[0]).toBe(0x5a);
        expect(appendOperation.bytes[appendOperation.bytes.length - 1]).toBe(
            0x5a,
        );

        const overlongAppendPayload = new Uint8Array(49_153).fill(0x6b);
        const overlongAppendRequest = encodeRequest({
            maximumPayloadByteLength: 49_153n,
            operations: [
                {
                    kind: 2,
                    objectOrdinal: 9,
                    payload: overlongAppendPayload,
                    payloadByteLength: 49_153n,
                    position: 0n,
                    protection: 0,
                },
            ],
            requestSequence: 2n,
            runtimeBindingHash: runtimeBinding(0x37),
        });
        expect(() =>
            decodeCommonProofExternalMemoryRequest(overlongAppendRequest),
        ).toThrowError(expect.objectContaining({ code: 'MalformedRequest' }));
    });

    it('runs cancellation, authenticated resume, output verification, and durable application through installed custody', async () => {
        const generatedProofBytes = Uint8Array.from([8, 6, 7, 5, 3, 0, 9]);
        let completionAttemptCount = 0;
        let completionRetirementRetryCount = 0;
        const host = await openSameRealmCommonProofApplicationHost({
            decorateCommonProofCustody: (custody) =>
                Object.freeze({
                    ...custody,
                    completeVerifiedOutput: () => {
                        completionAttemptCount += 1;
                        if (completionAttemptCount === 1) {
                            return Promise.reject(
                                new Error(
                                    'Injected fail-once verified-output completion.',
                                ),
                            );
                        }
                        return custody.completeVerifiedOutput();
                    },
                    retire: async () => {
                        completionRetirementRetryCount += 1;
                        await custody.retire();
                    },
                }),
            proofBytes: generatedProofBytes,
        });
        let environment:
            | Awaited<
                  ReturnType<
                      typeof openCommonProofExecutionEnvironmentInInstalledCustodyWorker
                  >
              >
            | undefined;
        try {
            const cursorBytes = bytesFromHex(
                host.kernel.encodePrivateRandomCursor({
                    derivationContextHash: 'ab'.repeat(64),
                    family: 0x0200,
                    nextCounter: '37',
                    purpose: 2,
                    streamAttemptIdentifierHex: 'cd'.repeat(32),
                }).canonicalBytesHex,
            );
            const generationFixture =
                createInstalledCommonProofGenerationFixture(cursorBytes);
            const generationFamilyAdapter =
                openClosedWorkerCommonProofGenerationFamilyAdapter(
                    generationFixture.freshRuntime,
                    101,
                );
            const preparedOperation =
                prepareCommonProofGenerationInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        foundationActionRandomnessHandleIdentifier:
                            host.actionRandomnessHandleIdentifier,
                        generationFamilyAdapter,
                    },
                );
            environment =
                await openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    host.installedHost,
                    { preparedOperation },
                );
            await expect(
                openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    host.installedHost,
                    { preparedOperation },
                ),
            ).rejects.toMatchObject({ code: 'InvalidInput' });
            const cancellationController = new AbortController();
            await expect(
                runCommonProofGenerationInInstalledCustodyWorker(environment, {
                    signal: cancellationController.signal,
                    yieldControl: () => {
                        cancellationController.abort(
                            'participant interrupted generation',
                        );
                        return Promise.resolve();
                    },
                }),
            ).rejects.toMatchObject({ code: 'Cancelled' });
            const copiedResumeDescriptor =
                copyInstalledCommonProofCheckpointResumeDescriptor(environment);
            expect(copiedResumeDescriptor).toBeDefined();
            if (copiedResumeDescriptor !== undefined) {
                copiedResumeDescriptor.checkpointLineageIdentifier.fill(0);
                copiedResumeDescriptor.commonProofEnvironmentIdentifier.fill(0);
                for (const copiedCursorBytes of copiedResumeDescriptor.orderedPrivateRandomCursorBytes) {
                    copiedCursorBytes.fill(0);
                }
                copiedResumeDescriptor.stableAttemptBindingHash.fill(0);
            }
            const resumeDescriptor =
                await suspendCommonProofExecutionEnvironmentForAuthenticatedResumeInInstalledCustodyWorker(
                    environment,
                );
            environment = undefined;
            const resumedGenerationFamilyAdapter =
                openClosedWorkerCommonProofGenerationFamilyAdapter(
                    generationFixture.resumeRuntime,
                    102,
                );
            const resumedPreparedOperation =
                prepareCommonProofGenerationInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        foundationActionRandomnessHandleIdentifier:
                            host.actionRandomnessHandleIdentifier,
                        generationFamilyAdapter: resumedGenerationFamilyAdapter,
                    },
                );
            environment =
                await openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        preparedOperation: resumedPreparedOperation,
                        resumeDescriptor,
                    },
                );
            resumeDescriptor.checkpointLineageIdentifier.fill(0);
            resumeDescriptor.commonProofEnvironmentIdentifier.fill(0);
            for (const resumeCursorBytes of resumeDescriptor.orderedPrivateRandomCursorBytes) {
                resumeCursorBytes.fill(0);
            }
            resumeDescriptor.stableAttemptBindingHash.fill(0);
            await runCommonProofGenerationInInstalledCustodyWorker(
                environment,
                {
                    yieldControl: () => Promise.resolve(),
                },
            );
            expect([...generationFixture.outputBytes]).toEqual([
                ...generatedProofBytes,
            ]);
            expect(generationFixture.observations).toEqual({
                acknowledgedCheckpointCount: 1,
                cancelledOperationReleaseCount: 1,
                discardedGenerationFamilyAdapterCount: 0,
                freshStorageResponseCount: 4,
                generatedCapabilityReleaseCount: 1,
                outputReadbackCount: 1,
                prefixReplayResponseCount: 4,
            });

            host.fixture.capability.release();
            const verificationFamilyAdapter =
                openClosedWorkerCommonProofVerificationFamilyAdapter(
                    host.fixture.runtime,
                    51,
                );
            const currentDurableBindingIdentifier =
                (await host.workerScope.send(
                    'open-foundation-witness-durable-binding',
                    {
                        stateObjectIdentifier: 'c'.repeat(64),
                        witnessRoleIdentifier: host.witnessRoleIdentifier,
                    },
                )) as string;
            await expect(
                verifyAndApplyCommonProofInInstalledCustodyWorker(environment, {
                    durableBindingIdentifier: currentDurableBindingIdentifier,
                    verificationFamilyAdapter,
                    witnessRoleIdentifier: host.witnessRoleIdentifier,
                    yieldControl: () => Promise.resolve(),
                }),
            ).resolves.toBeUndefined();
            expect(completionAttemptCount).toBe(1);
            expect(completionRetirementRetryCount).toBe(1);
            expect(host.fixture.observations).toEqual({
                abortedApplicationCount: 0,
                confirmedApplicationCount: 1,
                preparedApplicationCount: 1,
                releasedCapabilityCount: 1,
            });
            const retiredEnvironment = environment;
            expect(() =>
                copyInstalledCommonProofCheckpointResumeDescriptor(
                    retiredEnvironment,
                ),
            ).toThrowError(expect.objectContaining({ code: 'InvalidInput' }));
            environment = undefined;

            const unusedGenerationFamilyAdapter =
                openClosedWorkerCommonProofGenerationFamilyAdapter(
                    generationFixture.freshRuntime,
                    103,
                );
            const operationRetiredWithActionRandomness =
                prepareCommonProofGenerationInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        foundationActionRandomnessHandleIdentifier:
                            host.actionRandomnessHandleIdentifier,
                        generationFamilyAdapter: unusedGenerationFamilyAdapter,
                    },
                );
            await host.workerScope.send(
                'close-foundation-action-randomness',
                host.actionRandomnessHandleIdentifier,
            );
            expect(
                generationFixture.observations
                    .discardedGenerationFamilyAdapterCount,
            ).toBe(1);
            await expect(
                openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    host.installedHost,
                    { preparedOperation: operationRetiredWithActionRandomness },
                ),
            ).rejects.toMatchObject({ code: 'InvalidInput' });
        } finally {
            if (environment !== undefined) {
                await closeCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    environment,
                ).catch(() => undefined);
            }
            await host.close();
        }
    });

    it('retains a prepared generation adapter until fail-once disposal succeeds', async () => {
        const host = await openSameRealmCommonProofApplicationHost();
        try {
            const cursorBytes = bytesFromHex(
                host.kernel.encodePrivateRandomCursor({
                    derivationContextHash: 'ab'.repeat(64),
                    family: 0x0200,
                    nextCounter: '37',
                    purpose: 2,
                    streamAttemptIdentifierHex: 'cd'.repeat(32),
                }).canonicalBytesHex,
            );
            const generationFixture =
                createInstalledCommonProofGenerationFixture(cursorBytes, {
                    failFirstGenerationFamilyAdapterDiscard: true,
                });
            const preparedOperation =
                prepareCommonProofGenerationInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        foundationActionRandomnessHandleIdentifier:
                            host.actionRandomnessHandleIdentifier,
                        generationFamilyAdapter:
                            openClosedWorkerCommonProofGenerationFamilyAdapter(
                                generationFixture.freshRuntime,
                                101,
                            ),
                    },
                );

            await expect(
                host.workerScope.send(
                    'close-foundation-action-randomness',
                    host.actionRandomnessHandleIdentifier,
                ),
            ).rejects.toMatchObject({ code: 'OwnedWorkerFailure' });
            expect(
                generationFixture.observations
                    .discardedGenerationFamilyAdapterCount,
            ).toBe(1);
            await expect(
                openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    host.installedHost,
                    { preparedOperation },
                ),
            ).rejects.toMatchObject({ code: 'InvalidInput' });

            await expect(
                host.workerScope.send(
                    'close-foundation-action-randomness',
                    host.actionRandomnessHandleIdentifier,
                ),
            ).resolves.toBeUndefined();
            expect(
                generationFixture.observations
                    .discardedGenerationFamilyAdapterCount,
            ).toBe(2);
            await expect(
                openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    host.installedHost,
                    { preparedOperation },
                ),
            ).rejects.toMatchObject({ code: 'InvalidInput' });
        } finally {
            await host.close();
        }
    });

    it('caps one prepared-or-executing proof chain without consuming rejected source adapters', async () => {
        const host = await openSameRealmCommonProofApplicationHost();
        let environment:
            | Awaited<
                  ReturnType<
                      typeof openCommonProofExecutionEnvironmentInInstalledCustodyWorker
                  >
              >
            | undefined;
        try {
            const cursorBytes = bytesFromHex(
                host.kernel.encodePrivateRandomCursor({
                    derivationContextHash: 'ab'.repeat(64),
                    family: 0x0200,
                    nextCounter: '37',
                    purpose: 2,
                    streamAttemptIdentifierHex: 'cd'.repeat(32),
                }).canonicalBytesHex,
            );
            const retainedFixture =
                createInstalledCommonProofGenerationFixture(cursorBytes);
            const preparedOperation =
                prepareCommonProofGenerationInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        foundationActionRandomnessHandleIdentifier:
                            host.actionRandomnessHandleIdentifier,
                        generationFamilyAdapter:
                            openClosedWorkerCommonProofGenerationFamilyAdapter(
                                retainedFixture.freshRuntime,
                                101,
                            ),
                    },
                );
            const rejectedPreparedFixture =
                createInstalledCommonProofGenerationFixture(cursorBytes);
            const rejectedPreparedAdapter =
                openClosedWorkerCommonProofGenerationFamilyAdapter(
                    rejectedPreparedFixture.freshRuntime,
                    101,
                );
            expect(() =>
                prepareCommonProofGenerationInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        foundationActionRandomnessHandleIdentifier:
                            host.actionRandomnessHandleIdentifier,
                        generationFamilyAdapter: rejectedPreparedAdapter,
                    },
                ),
            ).toThrowError(expect.objectContaining({ code: 'InvalidState' }));
            releaseClosedWorkerCommonProofGenerationFamilyAdapter(
                rejectedPreparedAdapter,
            );
            expect(
                rejectedPreparedFixture.observations
                    .discardedGenerationFamilyAdapterCount,
            ).toBe(1);

            environment =
                await openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    host.installedHost,
                    { preparedOperation },
                );
            expect(
                retainedFixture.observations
                    .discardedGenerationFamilyAdapterCount,
            ).toBe(0);
            const rejectedExecutingFixture =
                createInstalledCommonProofGenerationFixture(cursorBytes);
            const rejectedExecutingAdapter =
                openClosedWorkerCommonProofGenerationFamilyAdapter(
                    rejectedExecutingFixture.freshRuntime,
                    101,
                );
            expect(() =>
                prepareCommonProofGenerationInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        foundationActionRandomnessHandleIdentifier:
                            host.actionRandomnessHandleIdentifier,
                        generationFamilyAdapter: rejectedExecutingAdapter,
                    },
                ),
            ).toThrowError(expect.objectContaining({ code: 'InvalidState' }));
            releaseClosedWorkerCommonProofGenerationFamilyAdapter(
                rejectedExecutingAdapter,
            );
            expect(
                rejectedExecutingFixture.observations
                    .discardedGenerationFamilyAdapterCount,
            ).toBe(1);

            await closeCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                environment,
            );
            environment = undefined;
            expect(
                retainedFixture.observations
                    .discardedGenerationFamilyAdapterCount,
            ).toBe(1);
        } finally {
            if (environment !== undefined) {
                await closeCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    environment,
                ).catch(() => undefined);
            }
            await host.close();
        }
    });

    it('caps active checkpoint handles and preserves a refused source for retry after release', async () => {
        const host = await openSameRealmCommonProofApplicationHost();
        const checkpointIdentifiers: string[] = [];
        try {
            for (
                let checkpointIndex = 0;
                checkpointIndex < 64;
                checkpointIndex += 1
            ) {
                const streamAttemptIdentifier = new Uint8Array(32).fill(
                    checkpointIndex + 1,
                );
                const opened = (await host.workerScope.send(
                    'begin-checkpoint',
                    [streamAttemptIdentifier],
                )) as Readonly<{ checkpointIdentifier: string }>;
                checkpointIdentifiers.push(opened.checkpointIdentifier);
            }

            const refusedStreamAttemptIdentifier = new Uint8Array(32).fill(
                0xa5,
            );
            const retainedRefusedSource =
                refusedStreamAttemptIdentifier.slice();
            await expect(
                host.workerScope.send('begin-checkpoint', [
                    refusedStreamAttemptIdentifier,
                ]),
            ).rejects.toMatchObject({ code: 'InvalidState' });
            expect(refusedStreamAttemptIdentifier).toEqual(
                retainedRefusedSource,
            );

            const releasedCheckpointIdentifier = checkpointIdentifiers.shift();
            if (releasedCheckpointIdentifier === undefined) {
                throw new Error(
                    'The checkpoint capacity test opened no handle.',
                );
            }
            await host.workerScope.send(
                'evict-checkpoint',
                releasedCheckpointIdentifier,
            );
            const retried = (await host.workerScope.send('begin-checkpoint', [
                refusedStreamAttemptIdentifier,
            ])) as Readonly<{ checkpointIdentifier: string }>;
            checkpointIdentifiers.push(retried.checkpointIdentifier);

            for (const checkpointIdentifier of checkpointIdentifiers) {
                await host.workerScope.send(
                    'evict-checkpoint',
                    checkpointIdentifier,
                );
            }
            checkpointIdentifiers.length = 0;
        } finally {
            host.fixture.capability.release();
            await host.close();
        }
    });

    it('caps resumed checkpoint handles before store access and permits retry after an unrelated release', async () => {
        const host = await openSameRealmCommonProofApplicationHost();
        const checkpointIdentifiers: string[] = [];
        try {
            const persisted = (await host.workerScope.send(
                'begin-checkpoint',
                [],
            )) as Readonly<{ checkpointIdentifier: string }>;
            checkpointIdentifiers.push(persisted.checkpointIdentifier);
            const description = (await host.workerScope.send(
                'copy-checkpoint-description',
                persisted.checkpointIdentifier,
            )) as Readonly<{ checkpointLineageIdentifier: Uint8Array }>;
            const publicationIdentifier = (await host.workerScope.send(
                'begin-checkpoint-publication',
                {
                    boundary: createWorkerCheckpointBoundary(),
                    checkpointIdentifier: persisted.checkpointIdentifier,
                },
            )) as string;
            await host.workerScope.send('write-checkpoint-publication-chunk', {
                chunk: workerCheckpointStateBytes.slice(),
                publicationIdentifier,
            });
            await host.workerScope.send(
                'commit-checkpoint-publication',
                publicationIdentifier,
            );

            const unrelatedCheckpointIdentifiers: string[] = [];
            for (
                let checkpointIndex = 0;
                checkpointIndex < 63;
                checkpointIndex += 1
            ) {
                const opened = (await host.workerScope.send(
                    'begin-checkpoint',
                    [new Uint8Array(32).fill(checkpointIndex + 0x40)],
                )) as Readonly<{ checkpointIdentifier: string }>;
                unrelatedCheckpointIdentifiers.push(
                    opened.checkpointIdentifier,
                );
                checkpointIdentifiers.push(opened.checkpointIdentifier);
            }

            const resumeInput = {
                checkpointLineageIdentifier:
                    description.checkpointLineageIdentifier.slice(),
                expectedBoundary: createExpectedWorkerCheckpointBoundary(),
            };
            const retainedLineageIdentifier =
                resumeInput.checkpointLineageIdentifier.slice();
            await expect(
                host.workerScope.send('resume-checkpoint', resumeInput),
            ).rejects.toMatchObject({ code: 'InvalidState' });
            expect(resumeInput.checkpointLineageIdentifier).toEqual(
                retainedLineageIdentifier,
            );

            const releasedCheckpointIdentifier =
                unrelatedCheckpointIdentifiers.shift();
            if (releasedCheckpointIdentifier === undefined) {
                throw new Error(
                    'The resumed-checkpoint capacity test opened no unrelated handle.',
                );
            }
            await host.workerScope.send(
                'evict-checkpoint',
                releasedCheckpointIdentifier,
            );
            checkpointIdentifiers.splice(
                checkpointIdentifiers.indexOf(releasedCheckpointIdentifier),
                1,
            );
            const resumed = (await host.workerScope.send(
                'resume-checkpoint',
                resumeInput,
            )) as Readonly<{ checkpointIdentifier: string }>;
            checkpointIdentifiers.push(resumed.checkpointIdentifier);

            for (const checkpointIdentifier of checkpointIdentifiers) {
                await host.workerScope.send(
                    'evict-checkpoint',
                    checkpointIdentifier,
                );
            }
            checkpointIdentifiers.length = 0;
        } finally {
            host.fixture.capability.release();
            await host.close();
        }
    });

    it('refuses same-lineage checkpoint operations while a stream remains active', async () => {
        const host = await openSameRealmCommonProofApplicationHost();
        const checkpointIdentifiers: string[] = [];
        try {
            const opened = (await host.workerScope.send(
                'begin-checkpoint',
                [],
            )) as Readonly<{ checkpointIdentifier: string }>;
            checkpointIdentifiers.push(opened.checkpointIdentifier);
            const description = (await host.workerScope.send(
                'copy-checkpoint-description',
                opened.checkpointIdentifier,
            )) as Readonly<{ checkpointLineageIdentifier: Uint8Array }>;
            const resumeInput = {
                checkpointLineageIdentifier:
                    description.checkpointLineageIdentifier.slice(),
                expectedBoundary: createExpectedWorkerCheckpointBoundary(),
            };
            const publicationIdentifier = (await host.workerScope.send(
                'begin-checkpoint-publication',
                {
                    boundary: createWorkerCheckpointBoundary(),
                    checkpointIdentifier: opened.checkpointIdentifier,
                },
            )) as string;
            await host.workerScope.send('write-checkpoint-publication-chunk', {
                chunk: workerCheckpointStateBytes.slice(),
                publicationIdentifier,
            });

            await expect(
                host.workerScope.send(
                    'evict-checkpoint',
                    opened.checkpointIdentifier,
                ),
            ).rejects.toMatchObject({ code: 'InvalidState' });
            await expect(
                host.workerScope.send('resume-checkpoint', resumeInput),
            ).rejects.toMatchObject({ code: 'InvalidState' });

            await host.workerScope.send(
                'commit-checkpoint-publication',
                publicationIdentifier,
            );
            const resumed = (await host.workerScope.send(
                'resume-checkpoint',
                resumeInput,
            )) as Readonly<{ checkpointIdentifier: string }>;
            checkpointIdentifiers.push(resumed.checkpointIdentifier);
            const restoreIdentifier = (await host.workerScope.send(
                'begin-checkpoint-restore',
                resumed.checkpointIdentifier,
            )) as string;

            await expect(
                host.workerScope.send(
                    'evict-checkpoint',
                    resumed.checkpointIdentifier,
                ),
            ).rejects.toMatchObject({ code: 'InvalidState' });
            await expect(
                host.workerScope.send('resume-checkpoint', resumeInput),
            ).rejects.toMatchObject({ code: 'InvalidState' });
            await expect(
                host.workerScope.send('begin-checkpoint-publication', {
                    boundary: createWorkerCheckpointBoundary(),
                    checkpointIdentifier: opened.checkpointIdentifier,
                }),
            ).rejects.toMatchObject({ code: 'InvalidState' });

            await expect(
                host.workerScope.send(
                    'read-checkpoint-restore-chunk',
                    restoreIdentifier,
                ),
            ).resolves.toEqual({
                chunkBytes: workerCheckpointStateBytes,
                chunkIndex: 0,
                done: false,
            });
            await expect(
                host.workerScope.send(
                    'read-checkpoint-restore-chunk',
                    restoreIdentifier,
                ),
            ).resolves.toEqual({ done: true });
            for (const checkpointIdentifier of checkpointIdentifiers) {
                await host.workerScope.send(
                    'evict-checkpoint',
                    checkpointIdentifier,
                );
            }
            checkpointIdentifiers.length = 0;
        } finally {
            host.fixture.capability.release();
            await host.close();
        }
    });

    it('retains failed witness, randomness, and initialization cleanup ownership for retry', async () => {
        const host = await openSameRealmCommonProofApplicationHost({
            failActionRandomnessCloseAttemptNumbers: [1, 2, 3],
            failFirstFoundationWitnessClose: true,
        });
        try {
            await host.retainAdditionalFoundationInitializationBatches();
            host.fixture.capability.release();

            await expect(host.installedHost()).rejects.toMatchObject({
                code: 'OwnedWorkerFailure',
            });
            expect(host.cleanupAttemptCounts()).toEqual({
                actionRandomness: 3,
                foundationWitness: 9,
                stateObjectRelease: 0,
            });
            expect(host.ownedCustodyCloseCount()).toBe(0);

            await expect(host.installedHost()).resolves.toBeUndefined();
            expect(host.cleanupAttemptCounts()).toEqual({
                actionRandomness: 6,
                foundationWitness: 10,
                stateObjectRelease: 0,
            });
            expect(host.ownedCustodyCloseCount()).toBe(1);
        } finally {
            await host.close();
        }
    });

    it('retains malformed initialization rollback ownership until an exact cleanup retry succeeds', async () => {
        const host = await openSameRealmCommonProofApplicationHost({
            failActionRandomnessCloseAttemptNumbers: [1],
            firstAdditionalInitializationWitnessCount:
                foundationProfile.participantCount - 2,
        });
        try {
            await expect(
                host.commitAdditionalFoundationOperationInitialization(),
            ).rejects.toMatchObject({
                code: 'OwnedWorkerFailure',
            });
            expect(host.cleanupAttemptCounts()).toEqual({
                actionRandomness: 1,
                foundationWitness: 0,
                stateObjectRelease: 0,
            });
            expect(host.ownedCustodyCloseCount()).toBe(0);

            await expect(
                host.commitAdditionalFoundationOperationInitialization(),
            ).resolves.toMatch(/^[0-9a-f]{64}$/u);
            expect(host.cleanupAttemptCounts()).toEqual({
                actionRandomness: 2,
                foundationWitness: 0,
                stateObjectRelease: 0,
            });

            await expect(host.installedHost()).resolves.toBeUndefined();
            expect(host.cleanupAttemptCounts()).toEqual({
                actionRandomness: 4,
                foundationWitness: 0,
                stateObjectRelease: 0,
            });
            expect(host.ownedCustodyCloseCount()).toBe(1);
        } finally {
            host.fixture.capability.release();
            await host.close();
        }
    });

    it('preserves an exact initialization batch across failed activation rollback and cleanup retry', async () => {
        const host = await openSameRealmCommonProofApplicationHost({
            failFirstAdditionalActivationHeadComparison: true,
            failFoundationWitnessCloseAttemptNumbers: [1],
        });
        try {
            const batchIdentifier =
                await host.commitAdditionalFoundationOperationInitialization();

            await expect(
                host.activateFreshFoundationInitialization(batchIdentifier),
            ).rejects.toMatchObject({
                code: 'OwnedWorkerFailure',
            });
            expect(host.cleanupAttemptCounts()).toEqual({
                actionRandomness: 0,
                foundationWitness: 9,
                stateObjectRelease: 0,
            });
            expect(host.ownedCustodyCloseCount()).toBe(0);

            const activated =
                await host.activateFreshFoundationInitialization(
                    batchIdentifier,
                );
            expect(activated.orderedWitnessRoleHandleIdentifiers).toHaveLength(
                foundationProfile.participantCount - 1,
            );
            expect(host.cleanupAttemptCounts()).toEqual({
                actionRandomness: 0,
                foundationWitness: 10,
                stateObjectRelease: 0,
            });

            await expect(host.installedHost()).resolves.toBeUndefined();
            expect(host.cleanupAttemptCounts()).toEqual({
                actionRandomness: 2,
                foundationWitness: 28,
                stateObjectRelease: 0,
            });
            expect(host.ownedCustodyCloseCount()).toBe(1);
        } finally {
            host.fixture.capability.release();
            await host.close();
        }
    });

    it('retains a foundation state object until fail-once cleanup succeeds', async () => {
        const host = await openSameRealmCommonProofApplicationHost({
            failFirstStateObjectRelease: true,
        });
        try {
            await expect(
                host.retainFoundationStateReservationIntent(),
            ).resolves.toMatch(/^[0-9a-f]{64}$/u);
            host.fixture.capability.release();

            await expect(host.installedHost()).rejects.toMatchObject({
                code: 'OwnedWorkerFailure',
            });
            expect(host.cleanupAttemptCounts()).toEqual({
                actionRandomness: 1,
                foundationWitness: 0,
                stateObjectRelease: 1,
            });
            expect(host.ownedCustodyCloseCount()).toBe(0);

            await expect(host.installedHost()).resolves.toBeUndefined();
            expect(host.cleanupAttemptCounts()).toEqual({
                actionRandomness: 1,
                foundationWitness: 0,
                stateObjectRelease: 2,
            });
            expect(host.ownedCustodyCloseCount()).toBe(1);
        } finally {
            await host.close();
        }
    });

    it('drains an in-flight command before terminal worker cleanup', async () => {
        let releaseCommitGate: (() => void) | undefined;
        const commitGate = new Promise<void>((resolve) => {
            releaseCommitGate = resolve;
        });
        let reportCommitStarted: (() => void) | undefined;
        const commitStarted = new Promise<void>((resolve) => {
            reportCommitStarted = resolve;
        });
        const host = await openSameRealmCommonProofApplicationHost({
            additionalInitializationCommitGate: commitGate,
            onAdditionalInitializationCommitStarted: () =>
                reportCommitStarted?.(),
        });
        try {
            const inFlightCommit =
                host.retainAdditionalFoundationInitializationBatches();
            await commitStarted;

            host.workerScope.dispatchMalformedRequest({
                messageKind: 'malformed-concurrent-traffic',
            });
            expect(host.workerScope.terminalNotifications).toHaveLength(0);

            releaseCommitGate?.();
            await expect(inFlightCommit).rejects.toMatchObject({
                code: 'OwnedWorkerFailure',
            });
            expect(host.cleanupAttemptCounts()).toEqual({
                actionRandomness: 2,
                foundationWitness: 0,
                stateObjectRelease: 0,
            });
            expect(host.ownedCustodyCloseCount()).toBe(1);
            expect(host.workerScope.terminalNotifications).toHaveLength(1);
        } finally {
            releaseCommitGate?.();
            host.fixture.capability.release();
            await host.close();
        }
    });

    it('retains an authenticated resume descriptor until fail-once adapter disposal succeeds', async () => {
        const host = await openSameRealmCommonProofApplicationHost();
        let environment:
            | Awaited<
                  ReturnType<
                      typeof openCommonProofExecutionEnvironmentInInstalledCustodyWorker
                  >
              >
            | undefined;
        try {
            const cursorBytes = bytesFromHex(
                host.kernel.encodePrivateRandomCursor({
                    derivationContextHash: 'ab'.repeat(64),
                    family: 0x0200,
                    nextCounter: '37',
                    purpose: 2,
                    streamAttemptIdentifierHex: 'cd'.repeat(32),
                }).canonicalBytesHex,
            );
            const generationFixture =
                createInstalledCommonProofGenerationFixture(cursorBytes, {
                    failFirstGenerationFamilyAdapterDiscard: true,
                });
            const freshPreparedOperation =
                prepareCommonProofGenerationInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        foundationActionRandomnessHandleIdentifier:
                            host.actionRandomnessHandleIdentifier,
                        generationFamilyAdapter:
                            openClosedWorkerCommonProofGenerationFamilyAdapter(
                                generationFixture.freshRuntime,
                                101,
                            ),
                    },
                );
            environment =
                await openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    host.installedHost,
                    { preparedOperation: freshPreparedOperation },
                );
            const cancellationController = new AbortController();
            await expect(
                runCommonProofGenerationInInstalledCustodyWorker(environment, {
                    signal: cancellationController.signal,
                    yieldControl: () => {
                        cancellationController.abort(
                            'participant interrupted generation',
                        );
                        return Promise.resolve();
                    },
                }),
            ).rejects.toMatchObject({ code: 'Cancelled' });
            const initialResumeDescriptor =
                await suspendCommonProofExecutionEnvironmentForAuthenticatedResumeInInstalledCustodyWorker(
                    environment,
                );
            environment = undefined;
            const expectedCheckpointLineageIdentifier =
                initialResumeDescriptor.checkpointLineageIdentifier.slice();
            const expectedEnvironmentIdentifier =
                initialResumeDescriptor.commonProofEnvironmentIdentifier.slice();
            const expectedCursors =
                initialResumeDescriptor.orderedPrivateRandomCursorBytes.map(
                    (cursor) => cursor.slice(),
                );
            const expectedStableAttemptBindingHash =
                initialResumeDescriptor.stableAttemptBindingHash.slice();
            const resumedPreparedOperation =
                prepareCommonProofGenerationInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        foundationActionRandomnessHandleIdentifier:
                            host.actionRandomnessHandleIdentifier,
                        generationFamilyAdapter:
                            openClosedWorkerCommonProofGenerationFamilyAdapter(
                                generationFixture.resumeRuntime,
                                102,
                            ),
                    },
                );
            environment =
                await openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        preparedOperation: resumedPreparedOperation,
                        resumeDescriptor: initialResumeDescriptor,
                    },
                );
            initialResumeDescriptor.checkpointLineageIdentifier.fill(0);
            initialResumeDescriptor.commonProofEnvironmentIdentifier.fill(0);
            for (const resumeCursorBytes of initialResumeDescriptor.orderedPrivateRandomCursorBytes) {
                resumeCursorBytes.fill(0);
            }
            initialResumeDescriptor.stableAttemptBindingHash.fill(0);

            await expect(
                suspendCommonProofExecutionEnvironmentForAuthenticatedResumeInInstalledCustodyWorker(
                    environment,
                ),
            ).rejects.toMatchObject({ code: 'StorageFailure' });
            expect(
                generationFixture.observations
                    .discardedGenerationFamilyAdapterCount,
            ).toBe(1);
            expect(() =>
                copyInstalledCommonProofCheckpointResumeDescriptor(
                    environment!,
                ),
            ).toThrowError(expect.objectContaining({ code: 'InvalidInput' }));

            const retriedResumeDescriptor =
                await suspendCommonProofExecutionEnvironmentForAuthenticatedResumeInInstalledCustodyWorker(
                    environment,
                );
            environment = undefined;
            expect(
                generationFixture.observations
                    .discardedGenerationFamilyAdapterCount,
            ).toBe(2);
            expect([
                ...retriedResumeDescriptor.checkpointLineageIdentifier,
            ]).toEqual([...expectedCheckpointLineageIdentifier]);
            expect([
                ...retriedResumeDescriptor.commonProofEnvironmentIdentifier,
            ]).toEqual([...expectedEnvironmentIdentifier]);
            expect(
                retriedResumeDescriptor.orderedPrivateRandomCursorBytes.map(
                    (cursor) => [...cursor],
                ),
            ).toEqual(expectedCursors.map((cursor) => [...cursor]));
            expect([
                ...retriedResumeDescriptor.stableAttemptBindingHash,
            ]).toEqual([...expectedStableAttemptBindingHash]);
            retriedResumeDescriptor.checkpointLineageIdentifier.fill(0);
            retriedResumeDescriptor.commonProofEnvironmentIdentifier.fill(0);
            for (const cursor of retriedResumeDescriptor.orderedPrivateRandomCursorBytes) {
                cursor.fill(0);
            }
            retriedResumeDescriptor.stableAttemptBindingHash.fill(0);
            expectedCheckpointLineageIdentifier.fill(0);
            expectedEnvironmentIdentifier.fill(0);
            for (const cursor of expectedCursors) {
                cursor.fill(0);
            }
            expectedStableAttemptBindingHash.fill(0);
        } finally {
            if (environment !== undefined) {
                await closeCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    environment,
                ).catch(() => undefined);
            }
            await host.close();
        }
    });

    it('retains a verified capability until fail-once terminal disposal succeeds', async () => {
        const generatedProofBytes = Uint8Array.from([8, 6, 7, 5, 3, 0, 9]);
        const host = await openSameRealmCommonProofApplicationHost({
            failVerifiedCapabilityReleaseAttempt: 2,
            proofBytes: generatedProofBytes,
        });
        let environment:
            | Awaited<
                  ReturnType<
                      typeof openCommonProofExecutionEnvironmentInInstalledCustodyWorker
                  >
              >
            | undefined;
        try {
            const cursorBytes = bytesFromHex(
                host.kernel.encodePrivateRandomCursor({
                    derivationContextHash: 'ab'.repeat(64),
                    family: 0x0200,
                    nextCounter: '37',
                    purpose: 2,
                    streamAttemptIdentifierHex: 'cd'.repeat(32),
                }).canonicalBytesHex,
            );
            const generationFixture =
                createInstalledCommonProofGenerationFixture(cursorBytes);
            const freshPreparedOperation =
                prepareCommonProofGenerationInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        foundationActionRandomnessHandleIdentifier:
                            host.actionRandomnessHandleIdentifier,
                        generationFamilyAdapter:
                            openClosedWorkerCommonProofGenerationFamilyAdapter(
                                generationFixture.freshRuntime,
                                101,
                            ),
                    },
                );
            environment =
                await openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    host.installedHost,
                    { preparedOperation: freshPreparedOperation },
                );
            const cancellationController = new AbortController();
            await expect(
                runCommonProofGenerationInInstalledCustodyWorker(environment, {
                    signal: cancellationController.signal,
                    yieldControl: () => {
                        cancellationController.abort(
                            'participant interrupted generation',
                        );
                        return Promise.resolve();
                    },
                }),
            ).rejects.toMatchObject({ code: 'Cancelled' });
            const resumeDescriptor =
                await suspendCommonProofExecutionEnvironmentForAuthenticatedResumeInInstalledCustodyWorker(
                    environment,
                );
            environment = undefined;
            const resumedPreparedOperation =
                prepareCommonProofGenerationInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        foundationActionRandomnessHandleIdentifier:
                            host.actionRandomnessHandleIdentifier,
                        generationFamilyAdapter:
                            openClosedWorkerCommonProofGenerationFamilyAdapter(
                                generationFixture.resumeRuntime,
                                102,
                            ),
                    },
                );
            environment =
                await openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        preparedOperation: resumedPreparedOperation,
                        resumeDescriptor,
                    },
                );
            resumeDescriptor.checkpointLineageIdentifier.fill(0);
            resumeDescriptor.commonProofEnvironmentIdentifier.fill(0);
            for (const cursor of resumeDescriptor.orderedPrivateRandomCursorBytes) {
                cursor.fill(0);
            }
            resumeDescriptor.stableAttemptBindingHash.fill(0);
            await runCommonProofGenerationInInstalledCustodyWorker(
                environment,
                { yieldControl: () => Promise.resolve() },
            );

            host.fixture.capability.release();
            expect(host.fixture.observations.releasedCapabilityCount).toBe(1);
            const verificationFamilyAdapter =
                openClosedWorkerCommonProofVerificationFamilyAdapter(
                    host.fixture.runtime,
                    51,
                );
            const retiredEnvironment = environment;
            await expect(
                verifyAndApplyCommonProofInInstalledCustodyWorker(environment, {
                    durableBindingIdentifier: 'missing-durable-binding',
                    verificationFamilyAdapter,
                    witnessRoleIdentifier: host.witnessRoleIdentifier,
                    yieldControl: () => Promise.resolve(),
                }),
            ).rejects.toMatchObject({ code: 'OwnedWorkerFailure' });
            expect(host.fixture.observations.releasedCapabilityCount).toBe(3);
            await expect(
                closeCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    retiredEnvironment,
                ),
            ).rejects.toMatchObject({ code: 'InvalidInput' });
            environment = undefined;
        } finally {
            if (environment !== undefined) {
                await closeCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    environment,
                ).catch(() => undefined);
            }
            await host.close();
        }
    });

    it('retains action-randomness environments until fail-once retirement cleanup succeeds', async () => {
        let retirementAttemptCount = 0;
        const host = await openSameRealmCommonProofApplicationHost({
            decorateCommonProofCustody: (custody) =>
                Object.freeze({
                    ...custody,
                    retire: async () => {
                        retirementAttemptCount += 1;
                        if (retirementAttemptCount === 1) {
                            throw new Error(
                                'Injected fail-once installed retirement.',
                            );
                        }
                        await custody.retire();
                    },
                }),
        });
        let environment:
            | Awaited<
                  ReturnType<
                      typeof openCommonProofExecutionEnvironmentInInstalledCustodyWorker
                  >
              >
            | undefined;
        try {
            const cursorBytes = bytesFromHex(
                host.kernel.encodePrivateRandomCursor({
                    derivationContextHash: 'ab'.repeat(64),
                    family: 0x0200,
                    nextCounter: '37',
                    purpose: 2,
                    streamAttemptIdentifierHex: 'cd'.repeat(32),
                }).canonicalBytesHex,
            );
            const generationFixture =
                createInstalledCommonProofGenerationFixture(cursorBytes);
            const generationFamilyAdapter =
                openClosedWorkerCommonProofGenerationFamilyAdapter(
                    generationFixture.freshRuntime,
                    101,
                );
            const preparedOperation =
                prepareCommonProofGenerationInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        foundationActionRandomnessHandleIdentifier:
                            host.actionRandomnessHandleIdentifier,
                        generationFamilyAdapter,
                    },
                );
            environment =
                await openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    host.installedHost,
                    { preparedOperation },
                );

            await expect(
                host.workerScope.send(
                    'close-foundation-action-randomness',
                    host.actionRandomnessHandleIdentifier,
                ),
            ).rejects.toMatchObject({ code: 'OwnedWorkerFailure' });
            expect(retirementAttemptCount).toBe(1);
            await expect(
                host.workerScope.send(
                    'close-foundation-action-randomness',
                    host.actionRandomnessHandleIdentifier,
                ),
            ).resolves.toBeUndefined();
            expect(retirementAttemptCount).toBe(2);
            expect(
                generationFixture.observations
                    .discardedGenerationFamilyAdapterCount,
            ).toBe(1);
            environment = undefined;
        } finally {
            if (environment !== undefined) {
                await closeCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    environment,
                ).catch(() => undefined);
            }
            await host.close();
        }
    });

    it('permanently retires an installed resumed environment when checkpoint restoration is unusable', async () => {
        const host = await openSameRealmCommonProofApplicationHost();
        let environment:
            | Awaited<
                  ReturnType<
                      typeof openCommonProofExecutionEnvironmentInInstalledCustodyWorker
                  >
              >
            | undefined;
        try {
            const cursorBytes = bytesFromHex(
                host.kernel.encodePrivateRandomCursor({
                    derivationContextHash: 'ab'.repeat(64),
                    family: 0x0200,
                    nextCounter: '37',
                    purpose: 2,
                    streamAttemptIdentifierHex: 'cd'.repeat(32),
                }).canonicalBytesHex,
            );
            const generationFixture =
                createInstalledCommonProofGenerationFixture(cursorBytes, {
                    resumeCheckpointStateByteLength: 38,
                });
            const freshPreparedOperation =
                prepareCommonProofGenerationInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        foundationActionRandomnessHandleIdentifier:
                            host.actionRandomnessHandleIdentifier,
                        generationFamilyAdapter:
                            openClosedWorkerCommonProofGenerationFamilyAdapter(
                                generationFixture.freshRuntime,
                                101,
                            ),
                    },
                );
            environment =
                await openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    host.installedHost,
                    { preparedOperation: freshPreparedOperation },
                );
            const cancellationController = new AbortController();
            await expect(
                runCommonProofGenerationInInstalledCustodyWorker(environment, {
                    signal: cancellationController.signal,
                    yieldControl: () => {
                        cancellationController.abort(
                            'participant interrupted generation',
                        );
                        return Promise.resolve();
                    },
                }),
            ).rejects.toMatchObject({ code: 'Cancelled' });
            const resumeDescriptor =
                await suspendCommonProofExecutionEnvironmentForAuthenticatedResumeInInstalledCustodyWorker(
                    environment,
                );
            environment = undefined;
            const resumedPreparedOperation =
                prepareCommonProofGenerationInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        foundationActionRandomnessHandleIdentifier:
                            host.actionRandomnessHandleIdentifier,
                        generationFamilyAdapter:
                            openClosedWorkerCommonProofGenerationFamilyAdapter(
                                generationFixture.resumeRuntime,
                                102,
                            ),
                    },
                );
            environment =
                await openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        preparedOperation: resumedPreparedOperation,
                        resumeDescriptor,
                    },
                );
            resumeDescriptor.checkpointLineageIdentifier.fill(0);
            resumeDescriptor.commonProofEnvironmentIdentifier.fill(0);
            for (const resumeCursorBytes of resumeDescriptor.orderedPrivateRandomCursorBytes) {
                resumeCursorBytes.fill(0);
            }
            resumeDescriptor.stableAttemptBindingHash.fill(0);

            const retiredEnvironment = environment;
            await expect(
                runCommonProofGenerationInInstalledCustodyWorker(
                    retiredEnvironment,
                ),
            ).rejects.toMatchObject({
                code: 'StorageFailure',
                permanentRetirementRequired: true,
            });
            expect(generationFixture.resumeFamilyPreparationCount()).toBe(0);
            expect(
                generationFixture.observations
                    .discardedGenerationFamilyAdapterCount,
            ).toBe(1);
            expect(() =>
                copyInstalledCommonProofCheckpointResumeDescriptor(
                    retiredEnvironment,
                ),
            ).toThrowError(expect.objectContaining({ code: 'InvalidInput' }));
            await expect(
                closeCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    retiredEnvironment,
                ),
            ).rejects.toMatchObject({ code: 'InvalidInput' });
            environment = undefined;
        } finally {
            if (environment !== undefined) {
                await closeCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    environment,
                ).catch(() => undefined);
            }
            await host.close();
        }
    });

    it('drives storage, commit, exact readback, and opaque generation authority in order', async () => {
        const binding = runtimeBinding(0x41);
        const request = fourByteReadRequest(binding, 1n);
        const outputBytes = Uint8Array.from([7, 3, 9, 1, 4]);
        let phase = 0;
        let releasedCapabilityCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_begin_generation: (
                preparedGenerationHandle,
                statusPointer,
            ) => {
                expect(preparedGenerationHandle).toBe(41);
                writeUnsigned32(memory, statusPointer, 0);
                return 51;
            },
            sealed_lattice_common_proof_generation_poll: (
                operationHandle,
                pollKindPointer,
                primaryValuePointer,
                secondaryValuePointer,
            ) => {
                expect(operationHandle).toBe(51);
                if (phase === 0) {
                    phase = 1;
                    return writeGenerationPoll(
                        memory,
                        pollKindPointer,
                        primaryValuePointer,
                        secondaryValuePointer,
                        1,
                        1,
                        0,
                    );
                }
                if (phase === 1) {
                    return writeGenerationPoll(
                        memory,
                        pollKindPointer,
                        primaryValuePointer,
                        secondaryValuePointer,
                        2,
                        request.byteLength,
                        noSecondPollValue,
                    );
                }
                if (phase === 2) {
                    return writeGenerationPoll(
                        memory,
                        pollKindPointer,
                        primaryValuePointer,
                        secondaryValuePointer,
                        3,
                        0,
                        outputBytes.byteLength,
                    );
                }
                if (phase === 3) {
                    return writeGenerationPoll(
                        memory,
                        pollKindPointer,
                        primaryValuePointer,
                        secondaryValuePointer,
                        4,
                        0,
                        noSecondPollValue,
                    );
                }
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
            sealed_lattice_common_proof_generation_copy_storage_request: (
                operationHandle,
                outputPointer,
                outputLength,
            ) => {
                expect(operationHandle).toBe(51);
                expect(phase).toBe(1);
                expect(outputLength).toBe(request.byteLength);
                memoryBytes(memory, outputPointer, outputLength).set(request);
                return 0;
            },
            sealed_lattice_common_proof_generation_supply_storage_response: (
                operationHandle,
                responsePointer,
                responseLength,
            ) => {
                expect(operationHandle).toBe(51);
                expect(phase).toBe(1);
                const response = memoryBytes(
                    memory,
                    responsePointer,
                    responseLength,
                );
                expect(
                    new DataView(
                        response.buffer,
                        response.byteOffset,
                    ).getUint16(2, true),
                ).toBe(2);
                phase = 2;
                return 0;
            },
            sealed_lattice_common_proof_generation_copy_output_chunk: (
                operationHandle,
                expectedChunkIndex,
                outputPointer,
                outputLength,
            ) => {
                expect(operationHandle).toBe(51);
                expect(expectedChunkIndex).toBe(0);
                expect(phase).toBe(2);
                expect(outputLength).toBe(outputBytes.byteLength);
                memoryBytes(memory, outputPointer, outputLength).set(
                    outputBytes,
                );
                return 0;
            },
            sealed_lattice_common_proof_generation_acknowledge_output_chunk: (
                operationHandle,
                expectedChunkIndex,
            ) => {
                expect(operationHandle).toBe(51);
                expect(expectedChunkIndex).toBe(0);
                expect(phase).toBe(2);
                phase = 3;
                return 0;
            },
            sealed_lattice_common_proof_generation_confirm_output_readback: (
                operationHandle,
                chunkIndex,
                readbackPointer,
                readbackLength,
            ) => {
                expect(operationHandle).toBe(51);
                expect(chunkIndex).toBe(0);
                expect(phase).toBe(3);
                expect([
                    ...memoryBytes(memory, readbackPointer, readbackLength),
                ]).toEqual([...outputBytes]);
                phase = 4;
                return 0;
            },
            sealed_lattice_common_proof_generation_finish: (
                operationHandle,
                statusPointer,
            ) => {
                expect(operationHandle).toBe(51);
                expect(phase).toBe(4);
                writeUnsigned32(memory, statusPointer, 0);
                phase = 5;
                return 61;
            },
            sealed_lattice_common_proof_release_generated_proof: (
                capabilityHandle,
            ) => {
                expect(capabilityHandle).toBe(61);
                expect(phase).toBe(5);
                releasedCapabilityCount += 1;
                return 0;
            },
        }));
        const storageReadBytes = Uint8Array.from([5, 8, 13, 21]);
        const transferredReadResult = readResult(0, 7, 3n, [
            ...storageReadBytes,
        ]);
        const externalMemory: CommonProofExternalMemoryTransactionExecutor = {
            executeTransaction: (decodedRequest) => {
                expect(decodedRequest.requestSequence).toBe(1n);
                return Promise.resolve([transferredReadResult]);
            },
        };
        let committedArgument: Uint8Array<ArrayBuffer> | undefined;
        let committedOutput: Uint8Array<ArrayBuffer> | undefined;
        const outputStore: CommonProofCanonicalOutputStore = {
            commitChunk: (chunkIndex, chunkBytes) => {
                expect(chunkIndex).toBe(0);
                committedArgument = chunkBytes;
                committedOutput = chunkBytes.slice();
                return Promise.resolve();
            },
            readChunk: (chunkIndex, exactByteLength) => {
                expect(chunkIndex).toBe(0);
                expect(exactByteLength).toBe(outputBytes.byteLength);
                return Promise.resolve(
                    committedOutput?.slice() ?? new Uint8Array(),
                );
            },
        };
        let yieldCount = 0;

        const capability = await runPreparedCommonProofGenerationWorker(
            runtime,
            41,
            externalMemory,
            outputStore,
            {
                yieldControl: () => {
                    yieldCount += 1;
                    return Promise.resolve();
                },
            },
        );

        expect(yieldCount).toBe(1);
        expect([...(committedOutput ?? [])]).toEqual([...outputBytes]);
        expect([...(committedArgument ?? [])]).toEqual(
            Array(outputBytes.byteLength).fill(0),
        );
        expect([...storageReadBytes]).toEqual([5, 8, 13, 21]);
        expect([...transferredReadResult.bytes]).toEqual([0, 0, 0, 0]);
        capability.release();
        expect(releasedCapabilityCount).toBe(1);
        expect(() => capability.release()).toThrowError(
            expect.objectContaining({ code: 'KernelFailure' }),
        );
    });

    it('rejects a hostile read length before copying and clears the transferred buffer', async () => {
        class CopyDetectingBytes extends Uint8Array {
            public copyAttempted = false;

            public override slice(
                start?: number,
                end?: number,
            ): Uint8Array<ArrayBuffer> {
                this.copyAttempted = true;
                return super.slice(start, end);
            }
        }

        const binding = runtimeBinding(0x47);
        const request = fourByteReadRequest(binding, 1n);
        let retiredOperationCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_begin_generation: (
                preparedGenerationHandle,
                statusPointer,
            ) => {
                expect(preparedGenerationHandle).toBe(43);
                writeUnsigned32(memory, statusPointer, 0);
                return 53;
            },
            sealed_lattice_common_proof_generation_poll: (
                operationHandle,
                pollKindPointer,
                primaryValuePointer,
                secondaryValuePointer,
            ) => {
                expect(operationHandle).toBe(53);
                return writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    2,
                    request.byteLength,
                    noSecondPollValue,
                );
            },
            sealed_lattice_common_proof_generation_copy_storage_request: (
                operationHandle,
                outputPointer,
                outputByteLength,
            ) => {
                expect(operationHandle).toBe(53);
                expect(outputByteLength).toBe(request.byteLength);
                memoryBytes(memory, outputPointer, outputByteLength).set(
                    request,
                );
                return 0;
            },
            sealed_lattice_common_proof_generation_retire_failed: (
                operationHandle,
            ) => {
                expect(operationHandle).toBe(53);
                retiredOperationCount += 1;
                return 0;
            },
        }));
        const transferredBytes = new CopyDetectingBytes(5).fill(0xa7);

        await expect(
            runPreparedCommonProofGenerationWorker(
                runtime,
                43,
                {
                    executeTransaction: () =>
                        Promise.resolve([
                            {
                                bytes: transferredBytes,
                                objectOrdinal: 7,
                                offset: 3n,
                                operationIndex: 0,
                            },
                        ]),
                },
                {
                    commitChunk: () => Promise.resolve(),
                    readChunk: () => Promise.resolve(new Uint8Array()),
                },
            ),
        ).rejects.toMatchObject({
            code: 'WrongStorageResult',
            permanentRetirementRequired: true,
        });
        expect(transferredBytes.copyAttempted).toBe(false);
        expect([...transferredBytes]).toEqual([0, 0, 0, 0, 0]);
        expect(retiredOperationCount).toBe(1);
    });

    it('retires a noncanonical generated-output chunk sequence before storage commit', async () => {
        let retiredOperationCount = 0;
        let outputCommitCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_begin_generation: (
                preparedGenerationHandle,
                statusPointer,
            ) => {
                expect(preparedGenerationHandle).toBe(44);
                writeUnsigned32(memory, statusPointer, 0);
                return 54;
            },
            sealed_lattice_common_proof_generation_poll: (
                operationHandle,
                pollKindPointer,
                primaryValuePointer,
                secondaryValuePointer,
            ) => {
                expect(operationHandle).toBe(54);
                return writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    3,
                    1,
                    1,
                );
            },
            sealed_lattice_common_proof_generation_retire_failed: (
                operationHandle,
            ) => {
                expect(operationHandle).toBe(54);
                retiredOperationCount += 1;
                return 0;
            },
        }));

        await expect(
            runPreparedCommonProofGenerationWorker(
                runtime,
                44,
                { executeTransaction: () => Promise.resolve([]) },
                {
                    commitChunk: () => {
                        outputCommitCount += 1;
                        return Promise.resolve();
                    },
                    readChunk: () => Promise.resolve(new Uint8Array()),
                },
            ),
        ).rejects.toMatchObject({
            code: 'KernelFailure',
            permanentRetirementRequired: true,
        });
        expect(outputCommitCount).toBe(0);
        expect(retiredOperationCount).toBe(1);
    });

    it('retires generation before committing a chunk after a short terminal chunk', async () => {
        let nextChunkIndex = 0;
        let retiredOperationCount = 0;
        const committedChunkIndices: number[] = [];
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_begin_generation: (
                preparedGenerationHandle,
                statusPointer,
            ) => {
                expect(preparedGenerationHandle).toBe(45);
                writeUnsigned32(memory, statusPointer, 0);
                return 55;
            },
            sealed_lattice_common_proof_generation_poll: (
                operationHandle,
                pollKindPointer,
                primaryValuePointer,
                secondaryValuePointer,
            ) => {
                expect(operationHandle).toBe(55);
                return writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    3,
                    nextChunkIndex,
                    1,
                );
            },
            sealed_lattice_common_proof_generation_copy_output_chunk: (
                operationHandle,
                chunkIndex,
                outputPointer,
                outputByteLength,
            ) => {
                expect(operationHandle).toBe(55);
                expect(chunkIndex).toBe(nextChunkIndex);
                expect(outputByteLength).toBe(1);
                memoryBytes(memory, outputPointer, outputByteLength)[0] =
                    chunkIndex;
                return 0;
            },
            sealed_lattice_common_proof_generation_acknowledge_output_chunk: (
                operationHandle,
                chunkIndex,
            ) => {
                expect(operationHandle).toBe(55);
                expect(chunkIndex).toBe(nextChunkIndex);
                nextChunkIndex += 1;
                return 0;
            },
            sealed_lattice_common_proof_generation_retire_failed: (
                operationHandle,
            ) => {
                expect(operationHandle).toBe(55);
                expect(nextChunkIndex).toBe(1);
                retiredOperationCount += 1;
                return 0;
            },
        }));

        await expect(
            runPreparedCommonProofGenerationWorker(
                runtime,
                45,
                { executeTransaction: () => Promise.resolve([]) },
                {
                    commitChunk: (chunkIndex, chunkBytes) => {
                        expect([...chunkBytes]).toEqual([chunkIndex]);
                        committedChunkIndices.push(chunkIndex);
                        return Promise.resolve();
                    },
                    readChunk: () => Promise.resolve(new Uint8Array()),
                },
            ),
        ).rejects.toMatchObject({
            code: 'KernelFailure',
            permanentRetirementRequired: true,
        });
        expect(committedChunkIndices).toEqual([0]);
        expect(retiredOperationCount).toBe(1);
    });

    it('publishes and acknowledges a complete checkpoint before continuing', async () => {
        const fixture = createCheckpointGenerationKernelFixture();
        let publishedCheckpoint: CommonProofGenerationCheckpoint | undefined;
        let committedStateBytes: Uint8Array<ArrayBuffer> | undefined;
        let committedCursorBytes: Uint8Array<ArrayBuffer> | undefined;
        let committedStableAttemptBindingHash:
            | Uint8Array<ArrayBuffer>
            | undefined;
        const capability = await runPreparedCommonProofGenerationWorker(
            fixture.runtime,
            81,
            {
                executeTransaction: () =>
                    Promise.reject(
                        new Error(
                            'A checkpoint-only fixture has no storage request.',
                        ),
                    ),
            },
            {
                commitChunk: () =>
                    Promise.reject(
                        new Error(
                            'A checkpoint boundary emits no proof output.',
                        ),
                    ),
                readChunk: () =>
                    Promise.reject(
                        new Error(
                            'A checkpoint boundary reads no proof output.',
                        ),
                    ),
            },
            {
                checkpointCustody: {
                    publishAuthenticatedCheckpoint: (checkpoint) => {
                        publishedCheckpoint = checkpoint;
                        expect(checkpoint.safeBoundaryOrdinal).toBe(4);
                        committedStateBytes =
                            checkpoint.canonicalStateBytes.slice();
                        committedCursorBytes =
                            checkpoint.orderedPrivateRandomCursorBytes[0]?.slice();
                        committedStableAttemptBindingHash =
                            checkpoint.stableAttemptBindingHash.slice();
                        return Promise.resolve();
                    },
                    restoreAuthenticatedCheckpointState: () =>
                        Promise.reject(
                            new Error(
                                'Fresh generation does not restore state.',
                            ),
                        ),
                },
                yieldControl: () => Promise.resolve(),
            },
        );

        expect(fixture.observations.acknowledgedCheckpointCount).toBe(1);
        expect(fixture.observations.discardedCheckpointCount).toBe(0);
        expect(fixture.observations.retiredOperationCount).toBe(0);
        expect([...(committedStateBytes ?? [])]).toEqual([
            ...fixture.canonicalStateBytes,
        ]);
        expect([...(committedCursorBytes ?? [])]).toEqual([
            ...fixture.cursorBytes,
        ]);
        expect([...(committedStableAttemptBindingHash ?? [])]).toEqual([
            ...fixture.stableAttemptBindingHash,
        ]);
        expect(publishedCheckpoint).toBeDefined();
        if (publishedCheckpoint === undefined) {
            throw new Error('The checkpoint was not published.');
        }
        expect([...publishedCheckpoint.canonicalStateBytes]).toEqual(
            Array(fixture.canonicalStateBytes.byteLength).fill(0),
        );
        expect([
            ...publishedCheckpoint.orderedPrivateRandomCursorBytes[0],
        ]).toEqual(Array(fixture.cursorBytes.byteLength).fill(0));
        expect([...publishedCheckpoint.stableAttemptBindingHash]).toEqual(
            Array(hashByteLength).fill(0),
        );
        capability.release();
    });

    it('explicitly discards a ready checkpoint when custody is absent', async () => {
        const fixture = createCheckpointGenerationKernelFixture();
        const capability = await runPreparedCommonProofGenerationWorker(
            fixture.runtime,
            81,
            {
                executeTransaction: () => Promise.resolve([]),
            },
            {
                commitChunk: () => Promise.resolve(),
                readChunk: () => Promise.resolve(new Uint8Array()),
            },
            { yieldControl: () => Promise.resolve() },
        );

        expect(fixture.observations.acknowledgedCheckpointCount).toBe(0);
        expect(fixture.observations.discardedCheckpointCount).toBe(1);
        expect(fixture.observations.retiredOperationCount).toBe(0);
        capability.release();
    });

    it('permanently retires an ambiguous checkpoint publication and wipes the snapshot', async () => {
        const fixture = createCheckpointGenerationKernelFixture();
        const publicationError = new Error(
            'IndexedDB committed but its response was lost',
        );
        let attemptedCheckpoint: CommonProofGenerationCheckpoint | undefined;

        await expect(
            runPreparedCommonProofGenerationWorker(
                fixture.runtime,
                81,
                { executeTransaction: () => Promise.resolve([]) },
                {
                    commitChunk: () => Promise.resolve(),
                    readChunk: () => Promise.resolve(new Uint8Array()),
                },
                {
                    checkpointCustody: {
                        publishAuthenticatedCheckpoint: (checkpoint) => {
                            attemptedCheckpoint = checkpoint;
                            return Promise.reject(publicationError);
                        },
                        restoreAuthenticatedCheckpointState: () =>
                            Promise.reject(
                                new Error(
                                    'Fresh generation does not restore state.',
                                ),
                            ),
                    },
                    yieldControl: () => Promise.resolve(),
                },
            ),
        ).rejects.toMatchObject({
            code: 'StorageFailure',
            failureCause: publicationError,
            permanentRetirementRequired: true,
        });
        expect(fixture.observations.acknowledgedCheckpointCount).toBe(0);
        expect(fixture.observations.discardedCheckpointCount).toBe(0);
        expect(fixture.observations.retiredOperationCount).toBe(1);
        expect(attemptedCheckpoint).toBeDefined();
        if (attemptedCheckpoint === undefined) {
            throw new Error('The checkpoint publication was not attempted.');
        }
        expect([...attemptedCheckpoint.canonicalStateBytes]).toEqual(
            Array(fixture.canonicalStateBytes.byteLength).fill(0),
        );
        expect([...attemptedCheckpoint.stableAttemptBindingHash]).toEqual(
            Array(hashByteLength).fill(0),
        );
    });

    it('retires a checkpoint whose cursor corpus exceeds the aggregate worker bound', async () => {
        const fixture = createCheckpointGenerationKernelFixture([
            new Uint8Array(524_288).fill(0x31),
            new Uint8Array(524_288).fill(0x32),
            Uint8Array.of(0x33),
        ]);
        let publicationAttempted = false;

        await expect(
            runPreparedCommonProofGenerationWorker(
                fixture.runtime,
                81,
                { executeTransaction: () => Promise.resolve([]) },
                {
                    commitChunk: () => Promise.resolve(),
                    readChunk: () => Promise.resolve(new Uint8Array()),
                },
                {
                    checkpointCustody: {
                        publishAuthenticatedCheckpoint: () => {
                            publicationAttempted = true;
                            return Promise.resolve();
                        },
                        restoreAuthenticatedCheckpointState: () =>
                            Promise.reject(
                                new Error('A fresh operation cannot restore.'),
                            ),
                    },
                },
            ),
        ).rejects.toMatchObject({
            code: 'KernelFailure',
            permanentRetirementRequired: true,
        });
        expect(publicationAttempted).toBe(false);
        expect(fixture.observations.acknowledgedCheckpointCount).toBe(0);
        expect(fixture.observations.retiredOperationCount).toBe(1);
    });

    it('replays a lost-response transaction exactly once before resumed output', async () => {
        const binding = runtimeBinding(0x57);
        const replayRequest = encodeRequest({
            maximumPayloadByteLength: 2n,
            operations: [
                {
                    kind: 2,
                    objectOrdinal: 12,
                    payload: Uint8Array.from([4, 2]),
                    payloadByteLength: 2n,
                    position: 0n,
                    protection: 0,
                },
            ],
            requestSequence: 1n,
            runtimeBindingHash: binding,
        });
        const liveRequest = fourByteReadRequest(binding, 2n);
        const authenticatedCheckpointState = Uint8Array.from([
            11, 7, 5, 3, 2, 13, 17, 19,
        ]);
        const expectedOutputBytes = Uint8Array.from([8, 6, 7, 5, 3, 0, 9]);
        let phase = 0;
        let releasedCapabilityCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_describe_generation_family_adapter: (
                adapterHandle,
                runtimeBindingHashOutputPointer,
                verificationBindingHashOutputPointer,
                proofAttemptLineageIdentifierOutputPointer,
                statusPointer,
            ) => {
                expect(adapterHandle).toBe(72);
                memoryBytes(
                    memory,
                    runtimeBindingHashOutputPointer,
                    hashByteLength,
                ).set(binding);
                memoryBytes(
                    memory,
                    verificationBindingHashOutputPointer,
                    hashByteLength,
                ).fill(0x58);
                memoryBytes(
                    memory,
                    proofAttemptLineageIdentifierOutputPointer,
                    32,
                ).fill(0x59);
                writeUnsigned32(memory, statusPointer, 0);
                return 0;
            },
            sealed_lattice_common_proof_prepare_generation_family_adapter: (
                adapterHandle,
                checkpointPointer,
                checkpointByteLength,
                statusPointer,
            ) => {
                expect(adapterHandle).toBe(72);
                expect([
                    ...memoryBytes(
                        memory,
                        checkpointPointer,
                        checkpointByteLength,
                    ),
                ]).toEqual([...authenticatedCheckpointState]);
                writeUnsigned32(memory, statusPointer, 0);
                return 82;
            },
            sealed_lattice_common_proof_discard_generation_family_adapter: () =>
                0,
            sealed_lattice_common_proof_generation_checkpoint_state_byte_length:
                () => authenticatedCheckpointState.byteLength,
            sealed_lattice_common_proof_begin_generation: () => {
                throw new Error('Resume must not open a fresh operation.');
            },
            sealed_lattice_common_proof_resume_generation: (
                preparedGenerationHandle,
                checkpointPointer,
                checkpointByteLength,
                statusPointer,
            ) => {
                expect(preparedGenerationHandle).toBe(82);
                expect([
                    ...memoryBytes(
                        memory,
                        checkpointPointer,
                        checkpointByteLength,
                    ),
                ]).toEqual([...authenticatedCheckpointState]);
                writeUnsigned32(memory, statusPointer, 0);
                return 92;
            },
            sealed_lattice_common_proof_generation_poll: (
                operationHandle,
                pollKindPointer,
                primaryValuePointer,
                secondaryValuePointer,
            ) => {
                expect(operationHandle).toBe(92);
                if (phase === 0) {
                    return writeGenerationPoll(
                        memory,
                        pollKindPointer,
                        primaryValuePointer,
                        secondaryValuePointer,
                        2,
                        replayRequest.byteLength,
                        noSecondPollValue,
                    );
                }
                if (phase === 1) {
                    phase = 2;
                    return writeGenerationPoll(
                        memory,
                        pollKindPointer,
                        primaryValuePointer,
                        secondaryValuePointer,
                        7,
                        4,
                        noSecondPollValue,
                    );
                }
                if (phase === 2) {
                    return writeGenerationPoll(
                        memory,
                        pollKindPointer,
                        primaryValuePointer,
                        secondaryValuePointer,
                        2,
                        liveRequest.byteLength,
                        noSecondPollValue,
                    );
                }
                if (phase === 3) {
                    return writeGenerationPoll(
                        memory,
                        pollKindPointer,
                        primaryValuePointer,
                        secondaryValuePointer,
                        3,
                        0,
                        expectedOutputBytes.byteLength,
                    );
                }
                if (phase === 4) {
                    return writeGenerationPoll(
                        memory,
                        pollKindPointer,
                        primaryValuePointer,
                        secondaryValuePointer,
                        4,
                        0,
                        noSecondPollValue,
                    );
                }
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
            sealed_lattice_common_proof_generation_copy_storage_request: (
                operationHandle,
                outputPointer,
                outputByteLength,
            ) => {
                expect(operationHandle).toBe(92);
                const request = phase === 0 ? replayRequest : liveRequest;
                expect(outputByteLength).toBe(request.byteLength);
                memoryBytes(memory, outputPointer, outputByteLength).set(
                    request,
                );
                return 0;
            },
            sealed_lattice_common_proof_generation_supply_storage_response: (
                operationHandle,
            ) => {
                expect(operationHandle).toBe(92);
                expect([0, 2]).toContain(phase);
                phase += 1;
                return 0;
            },
            sealed_lattice_common_proof_generation_copy_output_chunk: (
                operationHandle,
                chunkIndex,
                outputPointer,
                outputByteLength,
            ) => {
                expect(operationHandle).toBe(92);
                expect(chunkIndex).toBe(0);
                expect(phase).toBe(3);
                memoryBytes(memory, outputPointer, outputByteLength).set(
                    expectedOutputBytes,
                );
                return 0;
            },
            sealed_lattice_common_proof_generation_acknowledge_output_chunk: (
                operationHandle,
                chunkIndex,
            ) => {
                expect(operationHandle).toBe(92);
                expect(chunkIndex).toBe(0);
                expect(phase).toBe(3);
                phase = 4;
                return 0;
            },
            sealed_lattice_common_proof_generation_confirm_output_readback: (
                operationHandle,
                chunkIndex,
                readbackPointer,
                readbackByteLength,
            ) => {
                expect(operationHandle).toBe(92);
                expect(chunkIndex).toBe(0);
                expect(phase).toBe(4);
                expect([
                    ...memoryBytes(memory, readbackPointer, readbackByteLength),
                ]).toEqual([...expectedOutputBytes]);
                phase = 5;
                return 0;
            },
            sealed_lattice_common_proof_generation_finish: (
                operationHandle,
                statusPointer,
            ) => {
                expect(operationHandle).toBe(92);
                expect(phase).toBe(5);
                writeUnsigned32(memory, statusPointer, 0);
                return 102;
            },
            sealed_lattice_common_proof_release_generated_proof: (
                capabilityHandle,
            ) => {
                expect(capabilityHandle).toBe(102);
                releasedCapabilityCount += 1;
                return 0;
            },
        }));
        const committedReplayRequest =
            decodeCommonProofExternalMemoryRequest(replayRequest);
        const underlyingWriteCount = 1;
        let prefixReplayCount = 0;
        let liveTransactionCount = 0;
        let committedOutputBytes: Uint8Array<ArrayBuffer> | undefined;
        const familyAdapter =
            openClosedWorkerCommonProofGenerationFamilyAdapter(runtime, 72);
        await runClosedWorkerCommonProofGenerationFamilyAdapter(
            familyAdapter,
            {
                executeTransaction: (request) => {
                    liveTransactionCount += 1;
                    expect(request.requestSequence).toBe(2n);
                    return Promise.resolve([
                        readResult(0, 7, 3n, [1, 1, 2, 3]),
                    ]);
                },
            },
            {
                commitChunk: (chunkIndex, chunkBytes) => {
                    expect(chunkIndex).toBe(0);
                    committedOutputBytes = chunkBytes.slice();
                    return Promise.resolve();
                },
                readChunk: (_chunkIndex, exactByteLength) => {
                    expect(exactByteLength).toBe(
                        expectedOutputBytes.byteLength,
                    );
                    return Promise.resolve(
                        committedOutputBytes?.slice() ?? new Uint8Array(),
                    );
                },
            },
            {
                resume: {
                    checkpointCustody: {
                        publishAuthenticatedCheckpoint: () =>
                            Promise.reject(
                                new Error(
                                    'The fixture emits no later checkpoint.',
                                ),
                            ),
                        restoreAuthenticatedCheckpointState: () =>
                            Promise.resolve(
                                authenticatedCheckpointState.slice(),
                            ),
                    },
                    prefixReplayExternalMemory: {
                        executeDeterministicPrefixReplayTransaction: (
                            request,
                        ) => {
                            prefixReplayCount += 1;
                            expect(request.requestSequence).toBe(1n);
                            expect([...request.requestDigest]).toEqual([
                                ...committedReplayRequest.requestDigest,
                            ]);
                            return Promise.resolve([]);
                        },
                    },
                },
                yieldControl: () => Promise.resolve(),
            },
        );

        expect(underlyingWriteCount).toBe(1);
        expect(prefixReplayCount).toBe(1);
        expect(liveTransactionCount).toBe(1);
        expect([...(committedOutputBytes ?? [])]).toEqual([
            ...expectedOutputBytes,
        ]);
        expect(releasedCapabilityCount).toBe(1);
    });

    it('authenticates checkpoint custody before preparing resumed family generation', async () => {
        const restorationError = new Error('Encrypted checkpoint is missing');
        let adapterDiscardCount = 0;
        let preparationCount = 0;
        let resumeCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_describe_generation_family_adapter: (
                adapterHandle,
                runtimeBindingHashOutputPointer,
                verificationBindingHashOutputPointer,
                proofAttemptLineageIdentifierOutputPointer,
                statusPointer,
            ) => {
                expect(adapterHandle).toBe(73);
                memoryBytes(
                    memory,
                    runtimeBindingHashOutputPointer,
                    hashByteLength,
                ).fill(0x11);
                memoryBytes(
                    memory,
                    verificationBindingHashOutputPointer,
                    hashByteLength,
                ).fill(0x22);
                memoryBytes(
                    memory,
                    proofAttemptLineageIdentifierOutputPointer,
                    32,
                ).fill(0x33);
                writeUnsigned32(memory, statusPointer, 0);
                return 0;
            },
            sealed_lattice_common_proof_discard_generation_family_adapter: (
                adapterHandle,
            ) => {
                expect(adapterHandle).toBe(73);
                adapterDiscardCount += 1;
                return 0;
            },
            sealed_lattice_common_proof_generation_checkpoint_state_byte_length:
                () => 37,
            sealed_lattice_common_proof_prepare_generation_family_adapter:
                () => {
                    preparationCount += 1;
                    return 83;
                },
            sealed_lattice_common_proof_resume_generation: (
                _preparedGenerationHandle,
                _checkpointPointer,
                _checkpointByteLength,
                _statusPointer,
            ) => {
                resumeCount += 1;
                return 0;
            },
        }));
        const familyAdapter =
            openClosedWorkerCommonProofGenerationFamilyAdapter(runtime, 73);

        await expect(
            runClosedWorkerCommonProofGenerationFamilyAdapter(
                familyAdapter,
                { executeTransaction: () => Promise.resolve([]) },
                {
                    commitChunk: () => Promise.resolve(),
                    readChunk: () => Promise.resolve(new Uint8Array()),
                },
                {
                    resume: {
                        checkpointCustody: {
                            publishAuthenticatedCheckpoint: () =>
                                Promise.resolve(),
                            restoreAuthenticatedCheckpointState: () =>
                                Promise.reject(restorationError),
                        },
                        prefixReplayExternalMemory: {
                            executeDeterministicPrefixReplayTransaction: () =>
                                Promise.resolve([]),
                        },
                    },
                },
            ),
        ).rejects.toMatchObject({
            code: 'StorageFailure',
            failureCause: restorationError,
            permanentRetirementRequired: true,
        });
        expect(adapterDiscardCount).toBe(1);
        expect(preparationCount).toBe(0);
        expect(resumeCount).toBe(0);
    });

    it('discards generation family authority when preparation fails before the FFI call', async () => {
        let adapterDiscardCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_describe_generation_family_adapter: (
                adapterHandle,
                runtimeBindingHashOutputPointer,
                verificationBindingHashOutputPointer,
                proofAttemptLineageIdentifierOutputPointer,
                statusPointer,
            ) => {
                expect(adapterHandle).toBe(74);
                memoryBytes(
                    memory,
                    runtimeBindingHashOutputPointer,
                    hashByteLength,
                ).fill(0x11);
                memoryBytes(
                    memory,
                    verificationBindingHashOutputPointer,
                    hashByteLength,
                ).fill(0x22);
                memoryBytes(
                    memory,
                    proofAttemptLineageIdentifierOutputPointer,
                    32,
                ).fill(0x33);
                writeUnsigned32(memory, statusPointer, 0);
                return 0;
            },
            sealed_lattice_common_proof_discard_generation_family_adapter: (
                adapterHandle,
            ) => {
                expect(adapterHandle).toBe(74);
                adapterDiscardCount += 1;
                return 0;
            },
        }));
        const familyAdapter =
            openClosedWorkerCommonProofGenerationFamilyAdapter(runtime, 74);

        await expect(
            runClosedWorkerCommonProofGenerationFamilyAdapter(
                familyAdapter,
                { executeTransaction: () => Promise.resolve([]) },
                {
                    commitChunk: () => Promise.resolve(),
                    readChunk: () => Promise.resolve(new Uint8Array()),
                },
            ),
        ).rejects.toMatchObject({
            code: 'KernelFailure',
            message:
                'Common-proof generation preparation consumed its exact deferred family authority and permanently retired the attempt.',
            permanentRetirementRequired: true,
        });
        expect(adapterDiscardCount).toBe(1);
    });

    it('permanently retires a generation adapter when its resume accessor throws', async () => {
        const optionError = new Error('Injected resume option accessor.');
        let adapterDiscardCount = 0;
        let preparationCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_describe_generation_family_adapter: (
                adapterHandle,
                runtimeBindingHashOutputPointer,
                verificationBindingHashOutputPointer,
                proofAttemptLineageIdentifierOutputPointer,
                statusPointer,
            ) => {
                expect(adapterHandle).toBe(77);
                memoryBytes(
                    memory,
                    runtimeBindingHashOutputPointer,
                    hashByteLength,
                ).fill(0x11);
                memoryBytes(
                    memory,
                    verificationBindingHashOutputPointer,
                    hashByteLength,
                ).fill(0x22);
                memoryBytes(
                    memory,
                    proofAttemptLineageIdentifierOutputPointer,
                    32,
                ).fill(0x33);
                writeUnsigned32(memory, statusPointer, 0);
                return 0;
            },
            sealed_lattice_common_proof_discard_generation_family_adapter: (
                adapterHandle,
            ) => {
                expect(adapterHandle).toBe(77);
                adapterDiscardCount += 1;
                return 0;
            },
            sealed_lattice_common_proof_prepare_generation_family_adapter:
                () => {
                    preparationCount += 1;
                    return 0;
                },
        }));
        const familyAdapter =
            openClosedWorkerCommonProofGenerationFamilyAdapter(runtime, 77);
        const options = Object.create(null, {
            resume: {
                get: () => {
                    throw optionError;
                },
            },
        }) as CommonProofGenerationWorkerOptions;

        await expect(
            runClosedWorkerCommonProofGenerationFamilyAdapter(
                familyAdapter,
                { executeTransaction: () => Promise.resolve([]) },
                {
                    commitChunk: () => Promise.resolve(),
                    readChunk: () => Promise.resolve(new Uint8Array()),
                },
                options,
            ),
        ).rejects.toMatchObject({
            code: 'KernelFailure',
            message:
                'The common-proof generation adapter could not adopt its worker options and was permanently retired.',
            permanentRetirementRequired: true,
        });
        expect(adapterDiscardCount).toBe(1);
        expect(preparationCount).toBe(0);
    });

    it('discards transferred family authority when adoption fails before description', () => {
        let adapterDescriptionCount = 0;
        let adapterDiscardCount = 0;
        const runtime = createMockKernelRuntime((_memory) => ({
            sealed_lattice_common_proof_describe_generation_family_adapter: (
                _adapterHandle,
                _runtimeBindingHashOutputPointer,
                _verificationBindingHashOutputPointer,
                _proofAttemptLineageIdentifierOutputPointer,
                _statusPointer,
            ) => {
                adapterDescriptionCount += 1;
                return 0;
            },
            sealed_lattice_common_proof_discard_generation_family_adapter: (
                adapterHandle,
            ) => {
                expect(adapterHandle).toBe(75);
                adapterDiscardCount += 1;
                return 0;
            },
        }));
        const outOfProfileContext = {
            ...runtime,
            memory: {
                buffer: { byteLength: 402_653_185 },
            } as WebAssembly.Memory,
        } as TranscriptCoreKernelCommandRuntime;

        expect(() =>
            openClosedWorkerCommonProofGenerationFamilyAdapter(
                outOfProfileContext,
                75,
            ),
        ).toThrowError(expect.objectContaining({ code: 'ResourceLimit' }));
        expect(adapterDescriptionCount).toBe(0);
        expect(adapterDiscardCount).toBe(1);
    });

    it('requires permanent retirement when generated capability release fails', async () => {
        let generatedCapabilityReleaseCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_describe_generation_family_adapter: (
                adapterHandle,
                runtimeBindingHashOutputPointer,
                verificationBindingHashOutputPointer,
                proofAttemptLineageIdentifierOutputPointer,
                statusPointer,
            ) => {
                expect(adapterHandle).toBe(76);
                memoryBytes(
                    memory,
                    runtimeBindingHashOutputPointer,
                    hashByteLength,
                ).fill(0x11);
                memoryBytes(
                    memory,
                    verificationBindingHashOutputPointer,
                    hashByteLength,
                ).fill(0x22);
                memoryBytes(
                    memory,
                    proofAttemptLineageIdentifierOutputPointer,
                    32,
                ).fill(0x33);
                writeUnsigned32(memory, statusPointer, 0);
                return 0;
            },
            sealed_lattice_common_proof_prepare_generation_family_adapter: (
                adapterHandle,
                checkpointPointer,
                checkpointByteLength,
                statusPointer,
            ) => {
                expect(adapterHandle).toBe(76);
                expect(checkpointPointer).toBe(0);
                expect(checkpointByteLength).toBe(0);
                writeUnsigned32(memory, statusPointer, 0);
                return 86;
            },
            sealed_lattice_common_proof_begin_generation: (
                preparedGenerationHandle,
                statusPointer,
            ) => {
                expect(preparedGenerationHandle).toBe(86);
                writeUnsigned32(memory, statusPointer, 0);
                return 96;
            },
            sealed_lattice_common_proof_generation_poll: (
                operationHandle,
                pollKindPointer,
                primaryValuePointer,
                secondaryValuePointer,
            ) => {
                expect(operationHandle).toBe(96);
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
            sealed_lattice_common_proof_generation_finish: (
                operationHandle,
                statusPointer,
            ) => {
                expect(operationHandle).toBe(96);
                writeUnsigned32(memory, statusPointer, 0);
                return 106;
            },
            sealed_lattice_common_proof_release_generated_proof: (
                capabilityHandle,
            ) => {
                expect(capabilityHandle).toBe(106);
                generatedCapabilityReleaseCount += 1;
                return 0x0001_0001;
            },
        }));
        const familyAdapter =
            openClosedWorkerCommonProofGenerationFamilyAdapter(runtime, 76);

        await expect(
            runClosedWorkerCommonProofGenerationFamilyAdapter(
                familyAdapter,
                { executeTransaction: () => Promise.resolve([]) },
                {
                    commitChunk: () => Promise.resolve(),
                    readChunk: () => Promise.resolve(new Uint8Array()),
                },
            ),
        ).rejects.toMatchObject({
            code: 'KernelFailure',
            permanentRetirementRequired: true,
        });
        expect(generatedCapabilityReleaseCount).toBe(1);
    });

    it('retires generation authority and preserves the browser storage failure', async () => {
        const binding = runtimeBinding(0x43);
        const request = fourByteReadRequest(binding, 1n);
        const storageError = new Error('IndexedDB transaction aborted');
        let retirementCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_begin_generation: (
                preparedGenerationHandle,
                statusPointer,
            ) => {
                expect(preparedGenerationHandle).toBe(43);
                writeUnsigned32(memory, statusPointer, 0);
                return 53;
            },
            sealed_lattice_common_proof_generation_poll: (
                operationHandle,
                pollKindPointer,
                primaryValuePointer,
                secondaryValuePointer,
            ) => {
                expect(operationHandle).toBe(53);
                return writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    2,
                    request.byteLength,
                    noSecondPollValue,
                );
            },
            sealed_lattice_common_proof_generation_copy_storage_request: (
                operationHandle,
                outputPointer,
                outputLength,
            ) => {
                expect(operationHandle).toBe(53);
                expect(outputLength).toBe(request.byteLength);
                memoryBytes(memory, outputPointer, outputLength).set(request);
                return 0;
            },
            sealed_lattice_common_proof_generation_retire_failed: (
                operationHandle,
            ) => {
                expect(operationHandle).toBe(53);
                retirementCount += 1;
                return retirementCount === 1 ? 0 : 1;
            },
            sealed_lattice_common_proof_generation_request_cancellation: () => {
                throw new Error(
                    'A failed browser transaction cannot enter graceful cancellation.',
                );
            },
        }));
        const externalMemory: CommonProofExternalMemoryTransactionExecutor = {
            executeTransaction: () => Promise.reject(storageError),
        };
        const unusedOutputStore: CommonProofCanonicalOutputStore = {
            commitChunk: () =>
                Promise.reject(
                    new Error('A failed transaction emits no output.'),
                ),
            readChunk: () =>
                Promise.reject(
                    new Error('A failed transaction has no output.'),
                ),
        };

        await expect(
            runPreparedCommonProofGenerationWorker(
                runtime,
                43,
                externalMemory,
                unusedOutputStore,
            ),
        ).rejects.toMatchObject({
            code: 'StorageFailure',
            failureCause: storageError,
            permanentRetirementRequired: true,
        });
        expect(retirementCount).toBe(1);
    });

    it('retires generation authority when finish fails before Rust consumes the operation', async () => {
        let retirementCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_begin_generation: (
                preparedGenerationHandle,
                statusPointer,
            ) => {
                expect(preparedGenerationHandle).toBe(44);
                writeUnsigned32(memory, statusPointer, 0);
                return 54;
            },
            sealed_lattice_common_proof_generation_poll: (
                operationHandle,
                pollKindPointer,
                primaryValuePointer,
                secondaryValuePointer,
            ) => {
                expect(operationHandle).toBe(54);
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
            sealed_lattice_common_proof_generation_retire_failed: (
                operationHandle,
            ) => {
                expect(operationHandle).toBe(54);
                retirementCount += 1;
                return 0;
            },
        }));

        await expect(
            runPreparedCommonProofGenerationWorker(
                runtime,
                44,
                { executeTransaction: () => Promise.resolve([]) },
                {
                    commitChunk: () => Promise.resolve(),
                    readChunk: () => Promise.resolve(new Uint8Array()),
                },
            ),
        ).rejects.toMatchObject({
            code: 'KernelFailure',
            permanentRetirementRequired: true,
        });
        expect(retirementCount).toBe(1);
    });

    it('finishes an issued transaction and drives cleanup after cancellation', async () => {
        const binding = runtimeBinding(0x42);
        const generationRequest = fourByteReadRequest(binding, 1n);
        const cleanupRequest = encodeRequest({
            maximumPayloadByteLength: 1n,
            operations: [
                {
                    kind: 5,
                    objectOrdinal: 7,
                    payloadByteLength: 0n,
                    position: 0n,
                    protection: 0,
                },
            ],
            requestSequence: 2n,
            runtimeBindingHash: binding,
        });
        let phase = 0;
        let cancellationRequested = false;
        let cleanupRequestObservedAfterCancellation = false;
        let cancelledOperationReleased = false;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_begin_generation: (
                preparedGenerationHandle,
                statusPointer,
            ) => {
                expect(preparedGenerationHandle).toBe(42);
                writeUnsigned32(memory, statusPointer, 0);
                return 52;
            },
            sealed_lattice_common_proof_generation_poll: (
                operationHandle,
                pollKindPointer,
                primaryValuePointer,
                secondaryValuePointer,
            ) => {
                expect(operationHandle).toBe(52);
                if (phase === 0) {
                    return writeGenerationPoll(
                        memory,
                        pollKindPointer,
                        primaryValuePointer,
                        secondaryValuePointer,
                        2,
                        generationRequest.byteLength,
                        noSecondPollValue,
                    );
                }
                if (phase === 1) {
                    cleanupRequestObservedAfterCancellation =
                        cancellationRequested;
                    return writeGenerationPoll(
                        memory,
                        pollKindPointer,
                        primaryValuePointer,
                        secondaryValuePointer,
                        2,
                        cleanupRequest.byteLength,
                        noSecondPollValue,
                    );
                }
                return writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    6,
                    0,
                    noSecondPollValue,
                );
            },
            sealed_lattice_common_proof_generation_copy_storage_request: (
                operationHandle,
                outputPointer,
                outputLength,
            ) => {
                expect(operationHandle).toBe(52);
                const currentRequest =
                    phase === 0 ? generationRequest : cleanupRequest;
                expect(outputLength).toBe(currentRequest.byteLength);
                memoryBytes(memory, outputPointer, outputLength).set(
                    currentRequest,
                );
                return 0;
            },
            sealed_lattice_common_proof_generation_supply_storage_response: (
                operationHandle,
                _responsePointer,
                _responseLength,
            ) => {
                expect(operationHandle).toBe(52);
                phase += 1;
                return 0;
            },
            sealed_lattice_common_proof_generation_request_cancellation: (
                operationHandle,
            ) => {
                expect(operationHandle).toBe(52);
                expect(phase).toBe(1);
                cancellationRequested = true;
                return 0;
            },
            sealed_lattice_common_proof_generation_release_cancelled: (
                operationHandle,
            ) => {
                expect(operationHandle).toBe(52);
                expect(phase).toBe(2);
                cancelledOperationReleased = true;
                return 0;
            },
        }));
        const controller = new AbortController();
        let transactionCount = 0;
        const observedRequestSequences: bigint[] = [];
        const externalMemory: CommonProofExternalMemoryTransactionExecutor = {
            executeTransaction: (requestValue) => {
                transactionCount += 1;
                observedRequestSequences.push(requestValue.requestSequence);
                if (requestValue.requestSequence === 1n) {
                    controller.abort('participant cancelled');
                    return Promise.resolve([
                        readResult(0, 7, 3n, [1, 2, 3, 4]),
                    ]);
                }
                return Promise.resolve([]);
            },
        };
        const unusedOutputStore: CommonProofCanonicalOutputStore = {
            commitChunk: () =>
                Promise.reject(new Error('Cancellation must not emit output.')),
            readChunk: () =>
                Promise.reject(new Error('Cancellation must not read output.')),
        };

        await expect(
            runPreparedCommonProofGenerationWorker(
                runtime,
                42,
                externalMemory,
                unusedOutputStore,
                { signal: controller.signal },
            ),
        ).rejects.toMatchObject({ code: 'Cancelled' });
        expect(transactionCount).toBe(2);
        expect(observedRequestSequences).toEqual([1n, 2n]);
        expect(cancellationRequested).toBe(true);
        expect(cleanupRequestObservedAfterCancellation).toBe(true);
        expect(cancelledOperationReleased).toBe(true);
    });

    it('streams committed chunks, services two exact readbacks, and returns opaque verification authority', async () => {
        const firstChunk = new Uint8Array(1_048_576).fill(0x6a);
        firstChunk[firstChunk.byteLength - 1] = 0x7b;
        const secondChunk = Uint8Array.from([3, 1, 4, 1, 5]);
        const committedChunks = [firstChunk, secondChunk] as const;
        const readChunkIndices: number[] = [];
        const issuedChunks: Uint8Array[] = [];
        const suppliedReadbackIndices: number[] = [];
        let absorbedChunkCount = 0;
        let pollStep = 0;
        let discardedCapabilityCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
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
                expect(chunkIndex).toBe(absorbedChunkCount);
                expect(chunkLength).toBe(
                    committedChunks[chunkIndex]?.byteLength,
                );
                const input = memoryBytes(memory, chunkPointer, chunkLength);
                expect(input[0]).toBe(committedChunks[chunkIndex]?.[0]);
                expect(input[input.byteLength - 1]).toBe(
                    committedChunks[chunkIndex]?.[
                        committedChunks[chunkIndex].byteLength - 1
                    ],
                );
                absorbedChunkCount += 1;
                return 0;
            },
            sealed_lattice_common_proof_verification_finish_input: (
                operationHandle,
            ) => {
                expect(operationHandle).toBe(72);
                expect(absorbedChunkCount).toBe(2);
                return 0;
            },
            sealed_lattice_common_proof_verification_poll: (
                operationHandle,
                pollKindPointer,
                primaryValuePointer,
                secondaryValuePointer,
            ) => {
                expect(operationHandle).toBe(72);
                const polls = [
                    [2, 0, noSecondPollValue],
                    [1, 1, 0],
                    [3, 0, noSecondPollValue],
                    [4, 9, noSecondPollValue],
                    [5, 0, noSecondPollValue],
                ] as const;
                const poll = polls[pollStep];
                if (poll === undefined) {
                    throw new Error(
                        'The verifier was polled after completion.',
                    );
                }
                pollStep += 1;
                return writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    poll[0],
                    poll[1],
                    poll[2],
                );
            },
            sealed_lattice_common_proof_verification_supply_readback_chunk: (
                operationHandle,
                chunkIndex,
                chunkPointer,
                chunkLength,
            ) => {
                expect(operationHandle).toBe(72);
                const expectedIndex =
                    suppliedReadbackIndices.length === 0 ? 1 : 0;
                expect(chunkIndex).toBe(expectedIndex);
                expect(chunkLength).toBe(
                    committedChunks[chunkIndex]?.byteLength,
                );
                expect([
                    ...memoryBytes(memory, chunkPointer, chunkLength),
                ]).toEqual([...committedChunks[chunkIndex]]);
                suppliedReadbackIndices.push(chunkIndex);
                return 0;
            },
            sealed_lattice_common_proof_verification_finish: (
                operationHandle,
                statusPointer,
            ) => {
                expect(operationHandle).toBe(72);
                expect(pollStep).toBe(5);
                expect(suppliedReadbackIndices).toEqual([1, 0]);
                writeUnsigned32(memory, statusPointer, 0);
                return 82;
            },
            sealed_lattice_common_proof_discard_verified_proof: (
                capabilityHandle,
            ) => {
                expect(capabilityHandle).toBe(82);
                discardedCapabilityCount += 1;
                return 0;
            },
        }));
        let declaredByteLengthReadCount = 0;
        const inputStore: AuthenticatedCommonProofInputStore = {
            get declaredByteLength() {
                declaredByteLengthReadCount += 1;
                return firstChunk.byteLength + secondChunk.byteLength;
            },
            readCommittedChunk: (chunkIndex, exactByteLength) => {
                readChunkIndices.push(chunkIndex);
                expect(exactByteLength).toBe(
                    committedChunks[chunkIndex]?.byteLength,
                );
                const issuedChunk = committedChunks[chunkIndex]?.slice();
                if (issuedChunk === undefined) {
                    return Promise.reject(new Error('Unknown chunk index.'));
                }
                issuedChunks.push(issuedChunk);
                return Promise.resolve(issuedChunk);
            },
        };
        let yieldCount = 0;

        const capability = await runPreparedCommonProofVerificationWorker(
            runtime,
            62,
            inputStore,
            {
                yieldControl: () => {
                    yieldCount += 1;
                    return Promise.resolve();
                },
            },
        );

        expect(readChunkIndices).toEqual([0, 1, 1, 0]);
        expect(declaredByteLengthReadCount).toBe(1);
        expect(yieldCount).toBe(6);
        expect(issuedChunks).toHaveLength(4);
        for (const issuedChunk of issuedChunks) {
            expect(issuedChunk.every((byte) => byte === 0)).toBe(true);
        }
        expect(Object.keys(capability)).toEqual(['release']);
        capability.release();
        expect(discardedCapabilityCount).toBe(1);
        expect(() => capability.release()).toThrowError(
            expect.objectContaining({ code: 'KernelFailure' }),
        );
    });

    it('zeros a transferred verification chunk whose authenticated length is wrong', async () => {
        let cancellationCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_begin_verification: (
                preparedVerificationHandle,
                statusPointer,
            ) => {
                expect(preparedVerificationHandle).toBe(66);
                writeUnsigned32(memory, statusPointer, 0);
                return 76;
            },
            sealed_lattice_common_proof_verification_cancel: (
                operationHandle,
            ) => {
                expect(operationHandle).toBe(76);
                cancellationCount += 1;
                return 0;
            },
        }));
        const transferredChunk = new Uint8Array(3).fill(0xa7);

        await expect(
            runPreparedCommonProofVerificationWorker(runtime, 66, {
                declaredByteLength: 4,
                readCommittedChunk: () => Promise.resolve(transferredChunk),
            }),
        ).rejects.toMatchObject({ code: 'WrongStorageResult' });
        expect([...transferredChunk]).toEqual([0, 0, 0]);
        expect(cancellationCount).toBe(1);
    });

    it('retires a family-prepared verifier rejected before Rust begin', async () => {
        let beginCount = 0;
        let discardedPreparedVerificationCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_describe_verification_family_adapter: (
                adapterHandle,
                verificationBindingHashOutputPointer,
                statusPointer,
            ) => {
                expect(adapterHandle).toBe(55);
                memoryBytes(
                    memory,
                    verificationBindingHashOutputPointer,
                    hashByteLength,
                ).fill(0xb8);
                writeUnsigned32(memory, statusPointer, 0);
                return 0;
            },
            sealed_lattice_common_proof_prepare_verification_family_adapter: (
                adapterHandle,
                statusPointer,
            ) => {
                expect(adapterHandle).toBe(55);
                writeUnsigned32(memory, statusPointer, 0);
                return 65;
            },
            sealed_lattice_common_proof_discard_prepared_verification: (
                preparedVerificationHandle,
            ) => {
                expect(preparedVerificationHandle).toBe(65);
                discardedPreparedVerificationCount += 1;
                return 0;
            },
            sealed_lattice_common_proof_begin_verification: () => {
                beginCount += 1;
                return 0;
            },
        }));
        const familyAdapter =
            openClosedWorkerCommonProofVerificationFamilyAdapter(runtime, 55);

        await expect(
            runClosedWorkerCommonProofVerificationFamilyAdapter(familyAdapter, {
                declaredByteLength: 0,
                readCommittedChunk: () =>
                    Promise.reject(
                        new Error('Invalid input must not be read.'),
                    ),
            }),
        ).rejects.toMatchObject({ code: 'ResourceLimit' });
        expect(beginCount).toBe(0);
        expect(discardedPreparedVerificationCount).toBe(1);
    });

    it('discards verification family authority when preparation fails before the FFI call', async () => {
        let adapterDiscardCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_describe_verification_family_adapter: (
                adapterHandle,
                verificationBindingHashOutputPointer,
                statusPointer,
            ) => {
                expect(adapterHandle).toBe(56);
                memoryBytes(
                    memory,
                    verificationBindingHashOutputPointer,
                    hashByteLength,
                ).fill(0xb8);
                writeUnsigned32(memory, statusPointer, 0);
                return 0;
            },
            sealed_lattice_common_proof_discard_verification_family_adapter: (
                adapterHandle,
            ) => {
                expect(adapterHandle).toBe(56);
                adapterDiscardCount += 1;
                return 0;
            },
        }));
        const familyAdapter =
            openClosedWorkerCommonProofVerificationFamilyAdapter(runtime, 56);

        await expect(
            runClosedWorkerCommonProofVerificationFamilyAdapter(familyAdapter, {
                declaredByteLength: 1,
                readCommittedChunk: () =>
                    Promise.reject(
                        new Error('Preparation failure must not read input.'),
                    ),
            }),
        ).rejects.toThrow(
            'The transcript-core kernel did not expose sealed_lattice_common_proof_prepare_verification_family_adapter.',
        );
        expect(adapterDiscardCount).toBe(1);
    });

    it('discards prepared verification when the yield callback accessor throws before begin', async () => {
        const accessorError = new Error('Injected yield callback accessor.');
        let beginCount = 0;
        let discardCount = 0;
        const runtime = createMockKernelRuntime((_memory) => ({
            sealed_lattice_common_proof_begin_verification: () => {
                beginCount += 1;
                return 0;
            },
            sealed_lattice_common_proof_discard_prepared_verification: (
                preparedVerificationHandle,
            ) => {
                expect(preparedVerificationHandle).toBe(67);
                discardCount += 1;
                return 0;
            },
        }));
        const options = Object.create(null, {
            yieldControl: {
                get: () => {
                    throw accessorError;
                },
            },
        }) as CommonProofVerificationWorkerOptions;

        await expect(
            runPreparedCommonProofVerificationWorker(
                runtime,
                67,
                {
                    declaredByteLength: 1,
                    readCommittedChunk: () => Promise.resolve(Uint8Array.of(1)),
                },
                options,
            ),
        ).rejects.toBe(accessorError);
        expect(beginCount).toBe(0);
        expect(discardCount).toBe(1);
    });

    it('cancels verification when finish fails before Rust consumes the operation', async () => {
        let cancellationCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_begin_verification: (
                preparedVerificationHandle,
                statusPointer,
            ) => {
                expect(preparedVerificationHandle).toBe(68);
                writeUnsigned32(memory, statusPointer, 0);
                return 78;
            },
            sealed_lattice_common_proof_verification_absorb_input_chunk: (
                operationHandle,
                chunkIndex,
                _chunkPointer,
                chunkByteLength,
            ) => {
                expect(operationHandle).toBe(78);
                expect(chunkIndex).toBe(0);
                expect(chunkByteLength).toBe(1);
                return 0;
            },
            sealed_lattice_common_proof_verification_finish_input: (
                operationHandle,
            ) => {
                expect(operationHandle).toBe(78);
                return 0;
            },
            sealed_lattice_common_proof_verification_poll: (
                operationHandle,
                pollKindPointer,
                primaryValuePointer,
                secondaryValuePointer,
            ) => {
                expect(operationHandle).toBe(78);
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
            sealed_lattice_common_proof_verification_cancel: (
                operationHandle,
            ) => {
                expect(operationHandle).toBe(78);
                cancellationCount += 1;
                return 0;
            },
        }));

        await expect(
            runPreparedCommonProofVerificationWorker(
                runtime,
                68,
                {
                    declaredByteLength: 1,
                    readCommittedChunk: () => Promise.resolve(Uint8Array.of(1)),
                },
                { yieldControl: () => Promise.resolve() },
            ),
        ).rejects.toThrow(
            'The transcript-core kernel did not expose sealed_lattice_common_proof_verification_finish.',
        );
        expect(cancellationCount).toBe(1);
    });

    it('accepts the exact selected proof stream ceiling and refuses one byte beyond it before opening the kernel', async () => {
        const maximumProofByteLength = 5_242_880;
        let absorbedByteLength = 0;
        let beginCount = 0;
        let discardedCapabilityCount = 0;
        let discardedPreparedVerificationCount = 0;
        const runtime = createMockKernelRuntime(
            (memory) => ({
                sealed_lattice_common_proof_begin_verification: (
                    preparedVerificationHandle,
                    statusPointer,
                ) => {
                    expect(preparedVerificationHandle).toBe(64);
                    beginCount += 1;
                    writeUnsigned32(memory, statusPointer, 0);
                    return 74;
                },
                sealed_lattice_common_proof_verification_absorb_input_chunk: (
                    operationHandle,
                    chunkIndex,
                    _chunkPointer,
                    chunkLength,
                ) => {
                    expect(operationHandle).toBe(74);
                    expect(chunkIndex).toBe(absorbedByteLength / 1_048_576);
                    absorbedByteLength += chunkLength;
                    return 0;
                },
                sealed_lattice_common_proof_verification_finish_input: (
                    operationHandle,
                ) => {
                    expect(operationHandle).toBe(74);
                    expect(absorbedByteLength).toBe(maximumProofByteLength);
                    return 0;
                },
                sealed_lattice_common_proof_verification_poll: (
                    operationHandle,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                ) => {
                    expect(operationHandle).toBe(74);
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
                    expect(operationHandle).toBe(74);
                    writeUnsigned32(memory, statusPointer, 0);
                    return 84;
                },
                sealed_lattice_common_proof_discard_verified_proof: (
                    capabilityHandle,
                ) => {
                    expect(capabilityHandle).toBe(84);
                    discardedCapabilityCount += 1;
                    return 0;
                },
                sealed_lattice_common_proof_discard_prepared_verification: (
                    preparedVerificationHandle,
                ) => {
                    expect(preparedVerificationHandle).toBe(65);
                    discardedPreparedVerificationCount += 1;
                    return 0;
                },
            }),
            160,
        );
        const exactCeilingStore: AuthenticatedCommonProofInputStore = {
            declaredByteLength: maximumProofByteLength,
            readCommittedChunk: (chunkIndex, exactByteLength) =>
                Promise.resolve(
                    new Uint8Array(exactByteLength).fill(chunkIndex + 1),
                ),
        };

        const capability = await runPreparedCommonProofVerificationWorker(
            runtime,
            64,
            exactCeilingStore,
            { yieldControl: () => Promise.resolve() },
        );
        expect(beginCount).toBe(1);
        capability.release();
        expect(discardedCapabilityCount).toBe(1);

        await expect(
            runPreparedCommonProofVerificationWorker(runtime, 65, {
                declaredByteLength: maximumProofByteLength + 1,
                readCommittedChunk: () =>
                    Promise.reject(
                        new Error('Out-of-profile input must not be read.'),
                    ),
            }),
        ).rejects.toMatchObject({ code: 'ResourceLimit' });
        expect(beginCount).toBe(1);
        expect(discardedPreparedVerificationCount).toBe(1);
    });

    it('cancels a live verifier after browser interruption without finishing input', async () => {
        const controller = new AbortController();
        let absorbedChunkCount = 0;
        let cancellationCount = 0;
        let issuedChunk: Uint8Array | undefined;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_begin_verification: (
                preparedVerificationHandle,
                statusPointer,
            ) => {
                expect(preparedVerificationHandle).toBe(63);
                writeUnsigned32(memory, statusPointer, 0);
                return 73;
            },
            sealed_lattice_common_proof_verification_absorb_input_chunk: (
                operationHandle,
                chunkIndex,
                chunkPointer,
                chunkLength,
            ) => {
                expect(operationHandle).toBe(73);
                expect(chunkIndex).toBe(0);
                expect([
                    ...memoryBytes(memory, chunkPointer, chunkLength),
                ]).toEqual([8, 6, 7, 5, 3, 0, 9]);
                absorbedChunkCount += 1;
                return 0;
            },
            sealed_lattice_common_proof_verification_cancel: (
                operationHandle,
            ) => {
                expect(operationHandle).toBe(73);
                cancellationCount += 1;
                return 0;
            },
        }));
        const inputStore: AuthenticatedCommonProofInputStore = {
            declaredByteLength: 7,
            readCommittedChunk: (_chunkIndex, exactByteLength) => {
                expect(exactByteLength).toBe(7);
                issuedChunk = Uint8Array.from([8, 6, 7, 5, 3, 0, 9]);
                return Promise.resolve(issuedChunk);
            },
        };

        await expect(
            runPreparedCommonProofVerificationWorker(runtime, 63, inputStore, {
                signal: controller.signal,
                yieldControl: () => {
                    controller.abort('browser operation interrupted');
                    return Promise.resolve();
                },
            }),
        ).rejects.toMatchObject({ code: 'Cancelled' });
        expect(absorbedChunkCount).toBe(1);
        expect(cancellationCount).toBe(1);
        expect(issuedChunk?.every((byte) => byte === 0)).toBe(true);
    });

    it('retires the verifier when hostile poll metadata requests an uncommitted chunk', async () => {
        let cancellationCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_begin_verification: (
                preparedVerificationHandle,
                statusPointer,
            ) => {
                expect(preparedVerificationHandle).toBe(64);
                writeUnsigned32(memory, statusPointer, 0);
                return 74;
            },
            sealed_lattice_common_proof_verification_absorb_input_chunk: () =>
                0,
            sealed_lattice_common_proof_verification_finish_input: () => 0,
            sealed_lattice_common_proof_verification_poll: (
                _operationHandle,
                pollKindPointer,
                primaryValuePointer,
                secondaryValuePointer,
            ) =>
                writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    1,
                    1,
                    noSecondPollValue,
                ),
            sealed_lattice_common_proof_verification_cancel: () => {
                cancellationCount += 1;
                return 0;
            },
        }));
        const inputStore: AuthenticatedCommonProofInputStore = {
            declaredByteLength: 3,
            readCommittedChunk: () =>
                Promise.resolve(Uint8Array.from([2, 7, 1])),
        };

        await expect(
            runPreparedCommonProofVerificationWorker(runtime, 64, inputStore, {
                yieldControl: () => Promise.resolve(),
            }),
        ).rejects.toMatchObject({ code: 'KernelFailure' });
        expect(cancellationCount).toBe(1);
    });

    it('applies only a genuinely completed verifier capability to one exact authenticated successor', async () => {
        const fixture = await createVerifiedApplicationFixture();
        const prepared = prepareVerifiedCommonProofApplication(
            fixture.capability,
            fixture.storageRootAccess,
            fixture.predecessor,
        );

        expect([...prepared.authorizationFrame]).toEqual([
            ...fixture.authorizationFrame,
        ]);
        expect([...prepared.proofApplicationSlotHash]).toEqual([
            ...fixture.proofApplicationSlotHash,
        ]);
        expect(() =>
            prepareVerifiedCommonProofApplication(
                fixture.capability,
                fixture.storageRootAccess,
                fixture.predecessor,
            ),
        ).toThrowError(expect.objectContaining({ code: 'KernelFailure' }));

        confirmVerifiedCommonProofApplication(
            prepared.authority,
            fixture.storageRootAccess,
            fixture.successor,
            prepared.authorizationFrame,
        );

        expect(fixture.observations).toMatchObject({
            abortedApplicationCount: 0,
            confirmedApplicationCount: 1,
            preparedApplicationCount: 1,
            releasedCapabilityCount: 0,
        });
        expect(() =>
            confirmVerifiedCommonProofApplication(
                prepared.authority,
                fixture.storageRootAccess,
                fixture.successor,
                fixture.authorizationFrame,
            ),
        ).toThrowError(expect.objectContaining({ code: 'KernelFailure' }));
        expect(() => fixture.capability.release()).toThrowError(
            expect.objectContaining({ code: 'KernelFailure' }),
        );
    });

    it('keeps a mismatched pending transition stale and restores the exact verifier capability only on abort', async () => {
        const fixture = await createVerifiedApplicationFixture();
        const prepared = prepareVerifiedCommonProofApplication(
            fixture.capability,
            fixture.storageRootAccess,
            fixture.predecessor,
        );
        const wrongSuccessor = Object.freeze({
            authenticatedHeadDigest:
                fixture.successor.authenticatedHeadDigest.slice(),
            freshnessSequence: fixture.successor.freshnessSequence + 1n,
            storageInstanceIdentity:
                fixture.successor.storageInstanceIdentity.slice(),
        });

        expect(() =>
            confirmVerifiedCommonProofApplication(
                prepared.authority,
                fixture.storageRootAccess,
                wrongSuccessor,
                prepared.authorizationFrame,
            ),
        ).toThrowError(expect.objectContaining({ code: 'KernelFailure' }));
        expect(fixture.observations.confirmedApplicationCount).toBe(0);

        abortVerifiedCommonProofApplication(prepared.authority);
        expect(fixture.observations.abortedApplicationCount).toBe(1);
        expect(() =>
            abortVerifiedCommonProofApplication(prepared.authority),
        ).toThrowError(expect.objectContaining({ code: 'KernelFailure' }));

        const retried = prepareVerifiedCommonProofApplication(
            fixture.capability,
            fixture.storageRootAccess,
            fixture.predecessor,
        );
        abortVerifiedCommonProofApplication(retried.authority);
        fixture.capability.release();
        expect(fixture.observations).toMatchObject({
            abortedApplicationCount: 2,
            confirmedApplicationCount: 0,
            preparedApplicationCount: 2,
            releasedCapabilityCount: 1,
        });
    });

    it('refuses a storage root from another WASM instance without consuming verifier authority', async () => {
        const fixture = await createVerifiedApplicationFixture();
        const otherRuntime = createMockKernelRuntime(() => ({}));

        expect(() =>
            prepareVerifiedCommonProofApplication(
                fixture.capability,
                {
                    ...fixture.storageRootAccess,
                    context: otherRuntime,
                },
                fixture.predecessor,
            ),
        ).toThrowError(expect.objectContaining({ code: 'KernelFailure' }));

        fixture.capability.release();
        expect(fixture.observations.releasedCapabilityCount).toBe(1);
    });
});
