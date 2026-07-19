import { refusalReasonCodes } from '@sealed-lattice/types';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
    verifyAcceptedSetupRelinearizationRoundOneAggregateInClosedWorker,
    verifyAcceptedSetupRelinearizationRoundOneInClosedWorker,
    verifyAcceptedSetupRelinearizationRoundTwoInClosedWorker,
    type AcceptedSetupRelinearizationComponentDescription,
    type AcceptedSetupRelinearizationVerificationInput,
} from '#packages/wasm/src/accepted-setup-relinearization-verification-runtime';
import { registerCommonProofKernelContext } from '#packages/wasm/src/transcript-core-bridge/common-proof-kernel-context';
import type { TranscriptCoreKernelCommandRuntime } from '#packages/wasm/src/transcript-core-bridge/kernel-runtime';
import type { TranscriptCoreKernel } from '#packages/wasm/src/transcript-core-bridge/kernel-types';

type RelinearizationFamily = 'roundOne' | 'roundOneAggregate' | 'roundTwo';

const boundaryMocks = vi.hoisted(() => {
    const activeContext: {
        value: TranscriptCoreKernelCommandRuntime | undefined;
    } = { value: undefined };
    const componentBytes = [
        Uint8Array.of(0xa1, 0xa2, 0xa3),
        Uint8Array.of(0xb1, 0xb2, 0xb3, 0xb4, 0xb5),
    ];
    const returnTruncatedRange = { value: false };
    const verifiedCapabilityRelease = vi.fn();
    const verifiedCapability = Object.freeze({
        release: verifiedCapabilityRelease,
    });
    return {
        activeContext,
        applyVerified: vi.fn(
            (
                _capability: unknown,
                _context: unknown,
                apply: (handle: number) => {
                    consumed: boolean;
                    result: unknown;
                },
            ) => apply(61).result,
        ),
        componentBytes,
        openVerificationAdapter: vi.fn(() => Object.freeze({})),
        releaseVerificationAdapter: vi.fn(),
        requireAssemblyOwner: vi.fn(() => ({ handle: 90 })),
        requireCatalogOwner: vi.fn(() => ({ handle: 91 })),
        returnTruncatedRange,
        runVerification: vi.fn(() => Promise.resolve(verifiedCapability)),
        verifiedCapabilityRelease,
    };
});

vi.mock('#packages/wasm/src/common-proof-worker-runtime/runtime', () => ({
    applyClosedWorkerVerifiedCommonProofCapability: boundaryMocks.applyVerified,
    openClosedWorkerCommonProofVerificationFamilyAdapter:
        boundaryMocks.openVerificationAdapter,
    releaseClosedWorkerCommonProofVerificationFamilyAdapter:
        boundaryMocks.releaseVerificationAdapter,
    runClosedWorkerCommonProofVerificationFamilyAdapter:
        boundaryMocks.runVerification,
}));

vi.mock('#packages/wasm/src/accepted-setup-assembly-runtime', () => ({
    readAcceptedSetupPrepackageEvaluatorComponentExactRange: (input: {
        exactByteLength: number;
        materialRoot: Uint8Array;
        sourceByteOffset: bigint;
    }) => {
        const componentOrdinal = input.materialRoot[0] - 1;
        const component = boundaryMocks.componentBytes[componentOrdinal];
        const start = Number(input.sourceByteOffset);
        const requested = component.slice(start, start + input.exactByteLength);
        return Promise.resolve(
            boundaryMocks.returnTruncatedRange.value
                ? requested.slice(0, Math.max(0, requested.byteLength - 1))
                : requested,
        );
    },
    requireAcceptedSetupEvaluatorSourceCatalogKernelOwner:
        boundaryMocks.requireCatalogOwner,
    requireAcceptedSetupVerificationAssemblyKernelOwner:
        boundaryMocks.requireAssemblyOwner,
}));

type FakeRelinearizationRuntime = Readonly<{
    absorbedComponents: Array<
        Readonly<{
            bytes: number[];
            componentOrdinal: number;
            descriptor: number[];
        }>
    >;
    discardedIngresses: number[];
    discardedTerminalSources: Array<
        Readonly<{ family: RelinearizationFamily; handle: number }>
    >;
    events: string[];
    finishVerificationStatus: { value: number };
    ingressBegins: Array<
        Readonly<{
            assemblyHandle: number;
            catalogHandle: number;
            family: RelinearizationFamily;
            statement: number[];
            suiteHandle: number;
        }>
    >;
    kernel: TranscriptCoreKernel;
    verificationFinishes: Array<
        Readonly<{
            family: RelinearizationFamily;
            proofHandle: number;
            terminalSourceHandle: number;
        }>
    >;
}>;

const writeStatus = (
    memory: WebAssembly.Memory,
    pointer: number,
    status: number,
): void => {
    new DataView(memory.buffer).setUint32(pointer, status, true);
};

const createFakeRuntime = (): FakeRelinearizationRuntime => {
    const memory = new WebAssembly.Memory({ initial: 3 });
    const allocations = new Map<number, number>();
    const absorbedComponents: FakeRelinearizationRuntime['absorbedComponents'] =
        [];
    const discardedIngresses: number[] = [];
    const discardedTerminalSources: FakeRelinearizationRuntime['discardedTerminalSources'] =
        [];
    const events: string[] = [];
    const finishVerificationStatus = { value: 0 };
    const ingressBegins: FakeRelinearizationRuntime['ingressBegins'] = [];
    const verificationFinishes: FakeRelinearizationRuntime['verificationFinishes'] =
        [];
    const verificationDescriptors = new Map<number, number[]>();
    const ingressFamilies = new Map<number, RelinearizationFamily>();
    let nextPointer = 2_048;
    let nextIngressHandle = 70;

    const allocate = (byteLength: number): number => {
        const pointer = Math.ceil(nextPointer / 8) * 8;
        nextPointer = pointer + byteLength;
        allocations.set(pointer, byteLength);
        return pointer;
    };
    const deallocate = (pointer: number, byteLength: number): void => {
        if (allocations.get(pointer) !== byteLength) {
            throw new Error(
                'The fake relinearization allocation length changed.',
            );
        }
        allocations.delete(pointer);
    };
    const beginIngress =
        (family: RelinearizationFamily) =>
        (
            suiteHandle: number,
            assemblyHandle: number,
            catalogHandle: number,
            statementPointer: number,
            statementByteLength: number,
            statusPointer: number,
        ): number => {
            const handle = nextIngressHandle;
            nextIngressHandle += 1;
            ingressFamilies.set(handle, family);
            ingressBegins.push({
                assemblyHandle,
                catalogHandle,
                family,
                statement: Array.from(
                    new Uint8Array(
                        memory.buffer,
                        statementPointer,
                        statementByteLength,
                    ),
                ),
                suiteHandle,
            });
            events.push(`${family}:ingress`);
            writeStatus(memory, statusPointer, 0);
            return handle;
        };
    const finishVerification =
        (family: RelinearizationFamily) =>
        (proofHandle: number, terminalSourceHandle: number): number => {
            events.push(`${family}:terminal`);
            verificationFinishes.push({
                family,
                proofHandle,
                terminalSourceHandle,
            });
            return finishVerificationStatus.value;
        };
    const discardTerminalSource =
        (family: RelinearizationFamily) =>
        (handle: number): number => {
            discardedTerminalSources.push({ family, handle });
            return 0;
        };
    const wasmExports = {
        sealed_lattice_common_proof_release_suite: () => {
            events.push('suite:release');
            return 0;
        },
        sealed_lattice_common_proof_select_suite: (
            _pointer: number,
            _byteLength: number,
            statusPointer: number,
        ) => {
            events.push('suite:select');
            writeStatus(memory, statusPointer, 0);
            return 11;
        },
        sealed_lattice_relinearization_round_one_verification_ingress_begin:
            beginIngress('roundOne'),
        sealed_lattice_relinearization_round_one_aggregate_verification_ingress_begin:
            beginIngress('roundOneAggregate'),
        sealed_lattice_relinearization_round_two_verification_ingress_begin:
            beginIngress('roundTwo'),
        sealed_lattice_relinearization_verification_component_begin: (
            ingressHandle: number,
            componentOrdinal: number,
            descriptorPointer: number,
            descriptorByteLength: number,
        ) => {
            const family = ingressFamilies.get(ingressHandle)!;
            events.push(`${family}:component:${componentOrdinal}:begin`);
            verificationDescriptors.set(
                componentOrdinal,
                Array.from(
                    new Uint8Array(
                        memory.buffer,
                        descriptorPointer,
                        descriptorByteLength,
                    ),
                ),
            );
            return 0;
        },
        sealed_lattice_relinearization_verification_component_absorb_chunk: (
            ingressHandle: number,
            componentOrdinal: number,
            _chunkIndex: number,
            chunkPointer: number,
            chunkByteLength: number,
        ) => {
            const family = ingressFamilies.get(ingressHandle)!;
            events.push(`${family}:component:${componentOrdinal}:absorb`);
            absorbedComponents.push({
                bytes: Array.from(
                    new Uint8Array(
                        memory.buffer,
                        chunkPointer,
                        chunkByteLength,
                    ),
                ),
                componentOrdinal,
                descriptor: verificationDescriptors.get(componentOrdinal)!,
            });
            return 0;
        },
        sealed_lattice_relinearization_verification_component_finish: (
            ingressHandle: number,
            componentOrdinal: number,
        ) => {
            const family = ingressFamilies.get(ingressHandle)!;
            events.push(`${family}:component:${componentOrdinal}:finish`);
            return 0;
        },
        sealed_lattice_relinearization_prepare_verification: (
            ingressHandle: number,
            terminalPointer: number,
            statusPointer: number,
        ) => {
            const family = ingressFamilies.get(ingressHandle)!;
            events.push(`${family}:prepare`);
            new DataView(memory.buffer).setUint32(
                terminalPointer,
                80 + ingressHandle,
                true,
            );
            writeStatus(memory, statusPointer, 0);
            return 180 + ingressHandle;
        },
        sealed_lattice_relinearization_discard_verification_ingress: (
            handle: number,
        ) => {
            discardedIngresses.push(handle);
            return 0;
        },
        sealed_lattice_relinearization_round_one_finish_verification:
            finishVerification('roundOne'),
        sealed_lattice_relinearization_round_one_discard_verification_terminal_source:
            discardTerminalSource('roundOne'),
        sealed_lattice_relinearization_round_one_aggregate_finish_verification:
            finishVerification('roundOneAggregate'),
        sealed_lattice_relinearization_round_one_aggregate_discard_verification_terminal_source:
            discardTerminalSource('roundOneAggregate'),
        sealed_lattice_relinearization_round_two_finish_verification:
            finishVerification('roundTwo'),
        sealed_lattice_relinearization_round_two_discard_verification_terminal_source:
            discardTerminalSource('roundTwo'),
    };
    const kernel = Object.freeze({
        decodeStreamDescriptor: ({
            canonicalBytesHex,
        }: {
            canonicalBytesHex: string;
        }) => {
            const componentOrdinal = Number.parseInt(
                canonicalBytesHex.slice(0, 2),
                16,
            );
            const totalByteLength =
                boundaryMocks.componentBytes[componentOrdinal].byteLength;
            return {
                value: {
                    fullObjectDigest: (componentOrdinal + 31)
                        .toString(16)
                        .padStart(2, '0')
                        .repeat(64),
                    orderedChunkDigests: ['11'.repeat(64)],
                    totalByteLength: totalByteLength.toString(),
                },
            };
        },
    }) as unknown as TranscriptCoreKernel;
    const context = {
        allocate,
        deallocate,
        executeCommand: () => {
            throw new Error(
                'The focused relinearization test does not use commands.',
            );
        },
        memory,
        runExclusive: <Result>(
            _operationName: string,
            operation: () => Result,
        ): Result => operation(),
        wasmExports,
    } as unknown as TranscriptCoreKernelCommandRuntime;
    registerCommonProofKernelContext(kernel, context);
    boundaryMocks.activeContext.value = context;
    return Object.freeze({
        absorbedComponents,
        discardedIngresses,
        discardedTerminalSources,
        events,
        finishVerificationStatus,
        ingressBegins,
        kernel,
        verificationFinishes,
    });
};

const createComponents = (
    count: number,
): readonly AcceptedSetupRelinearizationComponentDescription[] =>
    Object.freeze(
        Array.from({ length: count }, (_, componentOrdinal) =>
            Object.freeze({
                materialRoot: new Uint8Array(64).fill(componentOrdinal + 1),
                streamDescriptorBytes: Uint8Array.of(componentOrdinal),
            }),
        ),
    );

const createInput = (
    runtime: FakeRelinearizationRuntime,
    components: readonly AcceptedSetupRelinearizationComponentDescription[],
): AcceptedSetupRelinearizationVerificationInput => ({
    acceptedSetupVerification: Object.freeze({}) as never,
    canonicalApplicationStatementBytes: Uint8Array.of(0xc1, 0xc2, 0xc3),
    canonicalSuiteRecordBytes: Uint8Array.of(1, 2, 3),
    components,
    evaluatorSourceCatalog: Object.freeze({}) as never,
    inputStore: Object.freeze({}) as never,
    kernel: runtime.kernel,
});

const familyCases = [
    {
        componentCount: 2,
        family: 'roundOne',
        verify: verifyAcceptedSetupRelinearizationRoundOneInClosedWorker,
    },
    {
        componentCount: 2,
        family: 'roundOneAggregate',
        verify: verifyAcceptedSetupRelinearizationRoundOneAggregateInClosedWorker,
    },
    {
        componentCount: 1,
        family: 'roundTwo',
        verify: verifyAcceptedSetupRelinearizationRoundTwoInClosedWorker,
    },
] as const;

beforeEach(() => {
    vi.clearAllMocks();
    boundaryMocks.returnTruncatedRange.value = false;
});

describe('accepted-setup relinearization verification runtime', () => {
    it.each(familyCases)(
        'streams the exact $family component topology before its positive terminal',
        async ({ componentCount, family, verify }) => {
            const runtime = createFakeRuntime();

            await verify(
                createInput(runtime, createComponents(componentCount)),
            );

            expect(runtime.ingressBegins).toEqual([
                {
                    assemblyHandle: 90,
                    catalogHandle: 91,
                    family,
                    statement: [0xc1, 0xc2, 0xc3],
                    suiteHandle: 11,
                },
            ]);
            expect(runtime.absorbedComponents).toEqual(
                Array.from(
                    { length: componentCount },
                    (_, componentOrdinal) => ({
                        bytes: Array.from(
                            boundaryMocks.componentBytes[componentOrdinal],
                        ),
                        componentOrdinal,
                        descriptor: [componentOrdinal],
                    }),
                ),
            );
            expect(runtime.verificationFinishes).toEqual([
                {
                    family,
                    proofHandle: 61,
                    terminalSourceHandle: 150,
                },
            ]);
            const preparationIndex = runtime.events.indexOf(
                `${family}:prepare`,
            );
            expect(preparationIndex).toBeGreaterThan(
                runtime.events.indexOf(
                    `${family}:component:${componentCount - 1}:finish`,
                ),
            );
            expect(
                runtime.events.indexOf(`${family}:terminal`),
            ).toBeGreaterThan(preparationIndex);
            expect(runtime.events.indexOf('suite:release')).toBeLessThan(
                runtime.events.indexOf(`${family}:terminal`),
            );
        },
    );

    it.each(familyCases)(
        'refuses a non-canonical $family component count before opening Rust ingress',
        async ({ componentCount, verify }) => {
            const runtime = createFakeRuntime();
            const wrongCount = componentCount === 1 ? 2 : 1;

            await expect(
                verify(createInput(runtime, createComponents(wrongCount))),
            ).rejects.toMatchObject({
                refusalReason: 'wrongTypeOrLength',
            });

            expect(runtime.ingressBegins).toEqual([]);
            expect(runtime.discardedIngresses).toEqual([]);
            expect(runtime.events).not.toContain('suite:select');
        },
    );

    it('discards round-one ingress when catalog custody returns a truncated range', async () => {
        const runtime = createFakeRuntime();
        boundaryMocks.returnTruncatedRange.value = true;

        await expect(
            verifyAcceptedSetupRelinearizationRoundOneInClosedWorker(
                createInput(runtime, createComponents(2)),
            ),
        ).rejects.toThrow(
            'The evaluator-source catalog returned a malformed relinearization component range.',
        );

        expect(runtime.discardedIngresses).toEqual([70]);
        expect(runtime.verificationFinishes).toEqual([]);
        expect(boundaryMocks.runVerification).not.toHaveBeenCalled();
    });

    it('releases generic proof authority and the aggregate terminal after refusal', async () => {
        const runtime = createFakeRuntime();
        runtime.finishVerificationStatus.value =
            refusalReasonCodes.invalidProof;

        await expect(
            verifyAcceptedSetupRelinearizationRoundOneAggregateInClosedWorker(
                createInput(runtime, createComponents(2)),
            ),
        ).rejects.toMatchObject({ refusalReason: 'invalidProof' });

        expect(boundaryMocks.verifiedCapabilityRelease).toHaveBeenCalledOnce();
        expect(runtime.discardedTerminalSources).toEqual([
            { family: 'roundOneAggregate', handle: 150 },
        ]);
    });
});
