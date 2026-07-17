import { describe, expect, it } from 'vitest';

import {
    abortVerifiedCommonProofApplication,
    confirmVerifiedCommonProofApplication,
    openClosedWorkerCommonProofVerificationFamilyAdapter,
    prepareVerifiedCommonProofApplication,
    runClosedWorkerCommonProofVerificationFamilyAdapter,
    runPreparedCommonProofVerificationWorker,
    type AuthenticatedCommonProofInputStore,
    type CommonProofVerificationWorkerOptions,
} from '../../../src/common-proof-worker-runtime.js';

import {
    createMockKernelRuntime,
    createVerifiedApplicationFixture,
    memoryBytes,
    noSecondPollValue,
    writeGenerationPoll,
    writeUnsigned32,
} from './kernel-fixtures.js';
import { hashByteLength } from './wire-fixtures.js';

describe('common-proof verification and application runtime', () => {
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
