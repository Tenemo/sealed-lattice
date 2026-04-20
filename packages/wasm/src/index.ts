/**
 * Typed byte-buffer kernel wrapper.
 *
 * The Rust crate currently exposes only the minimal buffer-allocation and
 * byte-round-trip contract needed to prove the long-lived WASM boundary before
 * cryptographic arithmetic is introduced.
 */

export type ByteBufferKernel = {
    readonly exportedFunctionNames: readonly string[];
    roundTripBytes(input: Uint8Array): Uint8Array;
};

type ByteBufferKernelExports = WebAssembly.Exports & {
    memory?: WebAssembly.Memory;
    sealed_lattice_allocate?: (length: number) => number;
    sealed_lattice_deallocate?: (pointer: number, length: number) => void;
    sealed_lattice_roundtrip?: (pointer: number, length: number) => number;
};

const byteBufferKernelUrl = new URL(
    '../dist/sealed-lattice-kernel.wasm',
    import.meta.url,
);

const resolveKernelBytes = async (): Promise<ArrayBuffer> => {
    /* v8 ignore next */
    if (byteBufferKernelUrl.protocol === 'file:') {
        const { readWasmFile } = await import('./node-wasm-file.js');

        return readWasmFile(byteBufferKernelUrl);
    }

    /* v8 ignore start */
    const response = await fetch(byteBufferKernelUrl);
    if (!response.ok) {
        throw new Error(
            `Failed to fetch the byte-buffer kernel from ${byteBufferKernelUrl.toString()}.`,
        );
    }

    return response.arrayBuffer();
    /* v8 ignore stop */
};

const resolveMemory = (
    exports: ByteBufferKernelExports,
): WebAssembly.Memory => {
    const { memory } = exports;
    /* v8 ignore next 3 */
    if (!(memory instanceof WebAssembly.Memory)) {
        throw new Error('The byte-buffer kernel did not expose linear memory.');
    }

    return memory;
};

const resolveNumberExport = (
    exports: ByteBufferKernelExports,
    exportName:
        | 'sealed_lattice_allocate'
        | 'sealed_lattice_deallocate'
        | 'sealed_lattice_roundtrip',
): ((...arguments_: number[]) => number | void) => {
    const exportValue = exports[exportName];
    /* v8 ignore next 3 */
    if (typeof exportValue !== 'function') {
        throw new Error(`The byte-buffer kernel did not expose ${exportName}.`);
    }

    return exportValue;
};

const copyIntoKernelMemory = (
    memory: WebAssembly.Memory,
    allocate: (length: number) => number,
    input: Uint8Array,
): number => {
    if (input.length === 0) {
        return 0;
    }

    const pointer = allocate(input.length);
    if (pointer === 0) {
        throw new Error(
            'The byte-buffer kernel returned a null pointer for a non-empty allocation.',
        );
    }

    new Uint8Array(memory.buffer).set(input, pointer);

    return pointer;
};

const copyFromKernelMemory = (
    memory: WebAssembly.Memory,
    pointer: number,
    length: number,
): Uint8Array => {
    if (length === 0) {
        return new Uint8Array();
    }
    if (pointer === 0) {
        throw new Error(
            'The byte-buffer kernel returned a null pointer for a non-empty round-trip result.',
        );
    }

    return Uint8Array.from(new Uint8Array(memory.buffer, pointer, length));
};

export const loadByteBufferKernel = async (): Promise<ByteBufferKernel> => {
    const bytes = await resolveKernelBytes();
    const instantiatedSource = await WebAssembly.instantiate(bytes, {});
    const exports = instantiatedSource.instance
        .exports as ByteBufferKernelExports;
    const memory = resolveMemory(exports);
    const allocate = resolveNumberExport(
        exports,
        'sealed_lattice_allocate',
    ) as (length: number) => number;
    const deallocate = resolveNumberExport(
        exports,
        'sealed_lattice_deallocate',
    ) as (pointer: number, length: number) => void;
    const roundtrip = resolveNumberExport(
        exports,
        'sealed_lattice_roundtrip',
    ) as (pointer: number, length: number) => number;
    const exportedFunctionNames = WebAssembly.Module.exports(
        instantiatedSource.module,
    )
        .map((entry) => entry.name)
        .sort();

    return {
        exportedFunctionNames,
        roundTripBytes: (input: Uint8Array): Uint8Array => {
            const normalizedInput = Uint8Array.from(input);
            let inputPointer = 0;
            let outputPointer = 0;

            try {
                inputPointer = copyIntoKernelMemory(
                    memory,
                    allocate,
                    normalizedInput,
                );
                outputPointer = roundtrip(inputPointer, normalizedInput.length);

                return copyFromKernelMemory(
                    memory,
                    outputPointer,
                    normalizedInput.length,
                );
            } finally {
                if (outputPointer !== 0) {
                    deallocate(outputPointer, normalizedInput.length);
                }
                if (inputPointer !== 0) {
                    deallocate(inputPointer, normalizedInput.length);
                }
            }
        },
    };
};

export const roundTripBytesThroughKernel = async (
    input: Uint8Array,
): Promise<Uint8Array> => {
    const kernel = await loadByteBufferKernel();

    return kernel.roundTripBytes(input);
};
