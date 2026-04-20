import { afterEach, describe, expect, it, vi } from 'vitest';

import {
    loadByteBufferKernel,
    roundTripBytesThroughKernel,
} from '../../src/index';

const createMockKernelExports = ({
    allocationPointer = 12,
    roundTripPointer = allocationPointer,
}: {
    allocationPointer?: number;
    roundTripPointer?: number;
} = {}): {
    deallocate: ReturnType<typeof vi.fn>;
} => {
    const deallocate = vi.fn();
    const fakeModule = {} as WebAssembly.Module;
    const webAssemblyWithByteSourceInstantiate = WebAssembly as unknown as {
        instantiate: (
            source: BufferSource,
            importObject?: WebAssembly.Imports,
        ) => Promise<WebAssembly.WebAssemblyInstantiatedSource>;
    };
    const instantiatedSource: WebAssembly.WebAssemblyInstantiatedSource = {
        instance: {
            exports: {
                memory: new WebAssembly.Memory({ initial: 1 }),
                sealed_lattice_allocate: vi.fn(() => allocationPointer),
                sealed_lattice_deallocate: deallocate,
                sealed_lattice_roundtrip: vi.fn(() => roundTripPointer),
            } as ByteBufferKernelExportsForTests,
        } as WebAssembly.Instance,
        module: fakeModule,
    };

    vi.spyOn(
        webAssemblyWithByteSourceInstantiate,
        'instantiate',
    ).mockResolvedValue(instantiatedSource);
    vi.spyOn(WebAssembly.Module, 'exports').mockReturnValue([
        { kind: 'memory', name: 'memory' },
        { kind: 'function', name: 'sealed_lattice_allocate' },
        { kind: 'function', name: 'sealed_lattice_deallocate' },
        { kind: 'function', name: 'sealed_lattice_roundtrip' },
    ]);

    return {
        deallocate,
    };
};

type ByteBufferKernelExportsForTests = WebAssembly.Exports & {
    memory: WebAssembly.Memory;
    sealed_lattice_allocate: () => number;
    sealed_lattice_deallocate: (pointer: number, length: number) => void;
    sealed_lattice_roundtrip: () => number;
};

afterEach(() => {
    vi.restoreAllMocks();
});

describe('byte-buffer kernel in Node', () => {
    it('loads the byte-buffer module and exposes the expected exports', async () => {
        const kernel = await loadByteBufferKernel();

        expect(kernel.exportedFunctionNames).toEqual(
            expect.arrayContaining([
                'memory',
                'sealed_lattice_allocate',
                'sealed_lattice_deallocate',
                'sealed_lattice_roundtrip',
            ]),
        );
    });

    it('round-trips empty and non-empty byte buffers', async () => {
        const kernel = await loadByteBufferKernel();

        expect(Array.from(kernel.roundTripBytes(new Uint8Array()))).toEqual([]);
        expect(
            Array.from(
                kernel.roundTripBytes(
                    Uint8Array.from([0, 1, 2, 127, 128, 255]),
                ),
            ),
        ).toEqual([0, 1, 2, 127, 128, 255]);
    });

    it('round-trips bytes through the async helper', async () => {
        await expect(
            roundTripBytesThroughKernel(Uint8Array.from([9, 8, 7, 6, 5])),
        ).resolves.toEqual(Uint8Array.from([9, 8, 7, 6, 5]));
    });

    it('rejects null pointers for non-empty allocations', async () => {
        createMockKernelExports({
            allocationPointer: 0,
        });
        const kernel = await loadByteBufferKernel();

        expect(() => kernel.roundTripBytes(Uint8Array.from([1]))).toThrow(
            'The byte-buffer kernel returned a null pointer for a non-empty allocation.',
        );
    });

    it('rejects null pointers for non-empty round-trip results', async () => {
        const { deallocate } = createMockKernelExports({
            allocationPointer: 12,
            roundTripPointer: 0,
        });
        const kernel = await loadByteBufferKernel();

        expect(() => kernel.roundTripBytes(Uint8Array.from([4, 5, 6]))).toThrow(
            'The byte-buffer kernel returned a null pointer for a non-empty round-trip result.',
        );
        expect(deallocate).toHaveBeenCalledTimes(1);
        expect(deallocate).toHaveBeenCalledWith(12, 3);
    });
});
