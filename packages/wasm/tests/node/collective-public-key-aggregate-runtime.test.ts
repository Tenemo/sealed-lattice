import { foundationProfile } from '@sealed-lattice/types';
import { describe, expect, it, vi } from 'vitest';

import type { AggregateThresholdShareRecipientAuthority } from '#packages/wasm/src/aggregate-threshold-share-authenticated-recipient';
import {
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
} from '#packages/wasm/src/canonical-stream-runtime';
import {
    beginCollectivePublicKeyAggregate,
    type CollectivePublicKeyParticipantSource,
} from '#packages/wasm/src/collective-public-key-aggregate-runtime';
import { registerCommonProofKernelContext } from '#packages/wasm/src/transcript-core-bridge/common-proof-kernel-context';
import type { TranscriptCoreKernelCommandRuntime } from '#packages/wasm/src/transcript-core-bridge/kernel-runtime';
import type { TranscriptCoreKernel } from '#packages/wasm/src/transcript-core-bridge/kernel-types';

type FakeCollectiveState = {
    readonly absorbedChunkCounts: number[];
    readonly allocations: Map<number, number>;
    readonly authority: AggregateThresholdShareRecipientAuthority;
    discardCount: number;
    readonly kernel: TranscriptCoreKernel;
    readonly memory: WebAssembly.Memory;
};

const fakeStates = vi.hoisted(() => new WeakMap<object, FakeCollectiveState>());

const testParticipantBodyByteLength =
    foundationProfile.streamChunkByteLength + 17;
const testParticipantChunkCount = Math.ceil(
    testParticipantBodyByteLength / foundationProfile.streamChunkByteLength,
);
const testAggregateBodyByteLength = testParticipantBodyByteLength * 2;

vi.mock(
    '#packages/wasm/src/aggregate-threshold-share-authenticated-recipient',
    () => ({
        requireAggregateThresholdShareRecipientAuthorityKernelOwner: (
            authority: AggregateThresholdShareRecipientAuthority,
            kernel: TranscriptCoreKernel,
        ) => {
            const state = fakeStates.get(kernel);
            if (state?.authority !== authority) {
                throw new CanonicalStreamRefusalError('wrongContext');
            }
            return Object.freeze({ handle: 17, kernel });
        },
    }),
);

const writeStatus = (
    memory: WebAssembly.Memory,
    pointer: number,
    status: number,
): void => {
    new DataView(memory.buffer).setUint32(pointer, status, true);
};

const createFakeCollectiveState = (): FakeCollectiveState => {
    const memory = new WebAssembly.Memory({ initial: 32 });
    const allocations = new Map<number, number>();
    const reusablePointers = new Map<number, number[]>();
    let nextPointer = 1024;
    const allocate = (byteLength: number): number => {
        const reusable = reusablePointers.get(byteLength)?.pop();
        if (reusable !== undefined) {
            allocations.set(reusable, byteLength);
            return reusable;
        }
        const pointer = Math.ceil(nextPointer / 8) * 8;
        nextPointer = pointer + byteLength;
        if (nextPointer > memory.buffer.byteLength) {
            memory.grow(
                Math.ceil((nextPointer - memory.buffer.byteLength) / 65_536),
            );
        }
        allocations.set(pointer, byteLength);
        return pointer;
    };
    const deallocate = (pointer: number, byteLength: number): void => {
        if (allocations.get(pointer) !== byteLength) {
            throw new Error(
                'The fake collective allocation had the wrong length.',
            );
        }
        allocations.delete(pointer);
        const reusable = reusablePointers.get(byteLength) ?? [];
        reusable.push(pointer);
        reusablePointers.set(byteLength, reusable);
    };
    const kernel = Object.freeze(Object.create(null)) as TranscriptCoreKernel;
    const authority = Object.freeze(
        Object.create(null),
    ) as AggregateThresholdShareRecipientAuthority;
    const state: FakeCollectiveState = {
        absorbedChunkCounts: Array.from(
            { length: foundationProfile.participantCount },
            () => 0,
        ),
        allocations,
        authority,
        discardCount: 0,
        kernel,
        memory,
    };
    let nextRosterPosition = 0;
    let activeRosterPosition: number | undefined;
    const context: TranscriptCoreKernelCommandRuntime = {
        allocate,
        deallocate,
        executeCommand: <Result>(): Result => {
            throw new Error('The fake collective kernel has no JSON command.');
        },
        memory,
        runExclusive: <Result>(
            _operationName: string,
            operation: () => Result,
        ): Result => operation(),
        wasmExports: {
            memory,
            sealed_lattice_collective_public_key_aggregate_absorb_participant_chunk:
                (
                    sessionHandle: number,
                    rosterPosition: number,
                    chunkIndex: number,
                    chunkPointer: number,
                    chunkByteLength: number,
                ) => {
                    expect(sessionHandle).toBe(11);
                    expect(rosterPosition).toBe(activeRosterPosition);
                    expect(chunkIndex).toBe(
                        state.absorbedChunkCounts[rosterPosition],
                    );
                    const expectedByteLength = Math.min(
                        foundationProfile.streamChunkByteLength,
                        testParticipantBodyByteLength -
                            chunkIndex *
                                foundationProfile.streamChunkByteLength,
                    );
                    expect(chunkByteLength).toBe(expectedByteLength);
                    const bytes = new Uint8Array(
                        memory.buffer,
                        chunkPointer,
                        chunkByteLength,
                    );
                    expect(bytes[0]).toBe(rosterPosition + 1);
                    expect(bytes[bytes.byteLength - 1]).toBe(
                        rosterPosition + 1,
                    );
                    state.absorbedChunkCounts[rosterPosition] += 1;
                    return 0;
                },
            sealed_lattice_collective_public_key_aggregate_begin: (
                authorityHandle: number,
                statusPointer: number,
            ) => {
                expect(authorityHandle).toBe(17);
                writeStatus(memory, statusPointer, 0);
                return 11;
            },
            sealed_lattice_collective_public_key_aggregate_begin_participant: (
                sessionHandle: number,
                rosterPosition: number,
                descriptorPointer: number,
                descriptorByteLength: number,
            ) => {
                expect(sessionHandle).toBe(11);
                expect(rosterPosition).toBe(nextRosterPosition);
                expect(activeRosterPosition).toBeUndefined();
                expect(
                    new Uint8Array(
                        memory.buffer,
                        descriptorPointer,
                        descriptorByteLength,
                    ),
                ).toEqual(Uint8Array.of(rosterPosition + 1));
                activeRosterPosition = rosterPosition;
                return 0;
            },
            sealed_lattice_collective_public_key_aggregate_commit_generated_proof:
                () => 0,
            sealed_lattice_collective_public_key_aggregate_contribute_package:
                () => 0,
            sealed_lattice_collective_public_key_aggregate_copy_participant_source_description:
                (
                    sessionHandle: number,
                    rosterPosition: number,
                    outputPointer: number,
                    outputByteLength: number,
                ) => {
                    expect(sessionHandle).toBe(11);
                    expect(rosterPosition).toBeLessThan(nextRosterPosition);
                    expect(outputByteLength).toBe(136);
                    const output = new Uint8Array(
                        memory.buffer,
                        outputPointer,
                        outputByteLength,
                    );
                    output.fill(0);
                    output[0] = rosterPosition + 1;
                    output[64] = rosterPosition + 33;
                    new DataView(memory.buffer).setBigUint64(
                        outputPointer + 128,
                        BigInt(testParticipantBodyByteLength),
                        true,
                    );
                    return 0;
                },
            sealed_lattice_collective_public_key_aggregate_copy_statement: (
                sessionHandle: number,
                outputPointer: number,
                outputByteLength: number,
            ) => {
                expect(sessionHandle).toBe(11);
                expect(outputByteLength).toBe(4);
                new Uint8Array(
                    memory.buffer,
                    outputPointer,
                    outputByteLength,
                ).set([1, 2, 3, 4]);
                return 0;
            },
            sealed_lattice_collective_public_key_aggregate_copy_stream_range:
                () => 0,
            sealed_lattice_collective_public_key_aggregate_describe_stream: (
                sessionHandle: number,
                outputPointer: number,
                outputByteLength: number,
            ) => {
                expect(sessionHandle).toBe(11);
                expect(outputByteLength).toBe(72);
                new DataView(memory.buffer).setBigUint64(
                    outputPointer,
                    BigInt(testAggregateBodyByteLength),
                    true,
                );
                new Uint8Array(memory.buffer, outputPointer + 8, 64).fill(0xa5);
                return 0;
            },
            sealed_lattice_collective_public_key_aggregate_discard_session: (
                sessionHandle: number,
            ) => {
                expect(sessionHandle).toBe(11);
                state.discardCount += 1;
                return 0;
            },
            sealed_lattice_collective_public_key_aggregate_discard_verification_terminal_source:
                () => 0,
            sealed_lattice_collective_public_key_aggregate_finish_participant: (
                sessionHandle: number,
                rosterPosition: number,
            ) => {
                expect(sessionHandle).toBe(11);
                expect(rosterPosition).toBe(activeRosterPosition);
                expect(state.absorbedChunkCounts[rosterPosition]).toBe(
                    testParticipantChunkCount,
                );
                activeRosterPosition = undefined;
                nextRosterPosition += 1;
                return 0;
            },
            sealed_lattice_collective_public_key_aggregate_finish_roster: (
                sessionHandle: number,
            ) => {
                expect(sessionHandle).toBe(11);
                expect(nextRosterPosition).toBe(
                    foundationProfile.participantCount,
                );
                return 0;
            },
            sealed_lattice_collective_public_key_aggregate_finish_verification:
                () => 0,
            sealed_lattice_collective_public_key_aggregate_participant_body_byte_length:
                () => BigInt(testParticipantBodyByteLength),
            sealed_lattice_collective_public_key_aggregate_prepare_generation:
                () => 1,
            sealed_lattice_collective_public_key_aggregate_prepare_resumed_generation:
                () => 1,
            sealed_lattice_collective_public_key_aggregate_prepare_verification:
                () => 1,
            sealed_lattice_collective_public_key_aggregate_statement_byte_length:
                (_sessionHandle: number, statusPointer: number) => {
                    writeStatus(memory, statusPointer, 0);
                    return 4n;
                },
        },
    };
    fakeStates.set(kernel, state);
    registerCommonProofKernelContext(kernel, context);
    return state;
};

const participantSources = (input: {
    malformedFirstChunk?: boolean;
}): readonly CollectivePublicKeyParticipantSource[] =>
    Object.freeze(
        Array.from(
            { length: foundationProfile.participantCount },
            (_, rosterPosition) =>
                Object.freeze({
                    descriptorBytes: Uint8Array.of(rosterPosition + 1),
                    inputStore: Object.freeze({
                        declaredByteLength: testParticipantBodyByteLength,
                        readCommittedChunk: (
                            chunkIndex: number,
                            exactByteLength: number,
                        ): Promise<Uint8Array> =>
                            Promise.resolve(
                                input.malformedFirstChunk === true &&
                                    rosterPosition === 0 &&
                                    chunkIndex === 0
                                    ? new Uint8Array(exactByteLength - 1)
                                    : new Uint8Array(exactByteLength).fill(
                                          rosterPosition + 1,
                                      ),
                            ),
                    }),
                }),
        ),
    );

describe('Collective public-key aggregate runtime', () => {
    it('ingests all roster-ordered authenticated participant chunks and retires cleanly', async () => {
        const state = createFakeCollectiveState();
        const aggregate = await beginCollectivePublicKeyAggregate({
            kernel: state.kernel,
            participantSources: participantSources({}),
            vssRecipientAuthority: state.authority,
        });

        expect(state.absorbedChunkCounts).toEqual(
            Array.from(
                { length: foundationProfile.participantCount },
                () => testParticipantChunkCount,
            ),
        );
        expect(aggregate.copyCanonicalApplicationStatement()).toEqual(
            Uint8Array.of(1, 2, 3, 4),
        );
        expect(aggregate.describeCollectivePublicKey()).toEqual({
            fullObjectDigest: new Uint8Array(64).fill(0xa5),
            totalByteLength: BigInt(testAggregateBodyByteLength),
        });

        aggregate.cancel();
        expect(state.discardCount).toBe(1);
        expect(state.allocations.size).toBe(0);
    });

    it('discards the Rust session when a browser store violates the owned-chunk contract', async () => {
        const state = createFakeCollectiveState();

        await expect(
            beginCollectivePublicKeyAggregate({
                kernel: state.kernel,
                participantSources: participantSources({
                    malformedFirstChunk: true,
                }),
                vssRecipientAuthority: state.authority,
            }),
        ).rejects.toBeInstanceOf(CanonicalStreamInternalError);
        expect(state.discardCount).toBe(1);
        expect(state.allocations.size).toBe(0);
    });

    it('rejects a non-selected participant store length before opening Rust state', async () => {
        const state = createFakeCollectiveState();
        const sources = [...participantSources({})];
        sources[0] = Object.freeze({
            ...sources[0],
            inputStore: Object.freeze({
                ...sources[0].inputStore,
                declaredByteLength: testParticipantBodyByteLength - 1,
            }),
        });

        await expect(
            beginCollectivePublicKeyAggregate({
                kernel: state.kernel,
                participantSources: sources,
                vssRecipientAuthority: state.authority,
            }),
        ).rejects.toMatchObject({ refusalReason: 'wrongTypeOrLength' });
        expect(state.discardCount).toBe(0);
        expect(state.allocations.size).toBe(0);
    });
});
