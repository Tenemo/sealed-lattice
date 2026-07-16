import { foundationProfile } from '@sealed-lattice/types';

const wasm32WordByteLength = 4;

type WasmMemoryContext = Readonly<{
    allocate(byteLength: number): number;
    deallocate(pointer: number, byteLength: number): void;
    memory: WebAssembly.Memory;
}>;

type WasmMemoryBoundaryOptions = Readonly<{
    context: WasmMemoryContext;
    createInternalError(message: string): Error;
    createResourceError(message: string): Error;
    label: string;
    observeMemoryByteLength?(byteLength: number): void;
}>;

export class WasmMemoryBoundary {
    readonly #context: WasmMemoryContext;
    readonly #createInternalError: (message: string) => Error;
    readonly #createResourceError: (message: string) => Error;
    readonly #label: string;
    readonly #observeMemoryByteLength:
        | ((byteLength: number) => void)
        | undefined;

    public constructor(options: WasmMemoryBoundaryOptions) {
        this.#context = options.context;
        this.#createInternalError = options.createInternalError;
        this.#createResourceError = options.createResourceError;
        this.#label = options.label;
        this.#observeMemoryByteLength = options.observeMemoryByteLength;
        this.assertWithinProfile();
    }

    public allocate(byteLength: number): number {
        this.validateAllocationByteLength(byteLength);

        const pointer = this.#context.allocate(byteLength) >>> 0;
        this.assertWithinProfile();
        if (
            pointer === 0 ||
            pointer + byteLength > this.#context.memory.buffer.byteLength
        ) {
            throw this.#createInternalError(
                `The WASM allocator returned an invalid ${this.#label} memory range.`,
            );
        }
        this.#observeMemoryByteLength?.(this.#context.memory.buffer.byteLength);
        return pointer;
    }

    public validateAllocationByteLength(byteLength: number): void {
        if (
            !Number.isSafeInteger(byteLength) ||
            byteLength <= 0 ||
            byteLength > foundationProfile.maximumCopiedBufferByteLength
        ) {
            throw this.#createResourceError(
                `The ${this.#label} allocation exceeds the WASM memory profile.`,
            );
        }
        this.assertWithinProfile();
    }

    public allocateZeroedWords(wordCount: number): number {
        if (!Number.isSafeInteger(wordCount) || wordCount <= 0) {
            throw this.#createInternalError(
                `The ${this.#label} metadata word count is invalid.`,
            );
        }
        const byteLength = wordCount * wasm32WordByteLength;
        const pointer = this.allocate(byteLength);
        new Uint8Array(this.#context.memory.buffer, pointer, byteLength).fill(
            0,
        );
        return pointer;
    }

    public copy(bytes: Uint8Array): number {
        const pointer = this.allocate(bytes.byteLength);
        try {
            new Uint8Array(this.#context.memory.buffer).set(bytes, pointer);
            return pointer;
        } catch (error) {
            this.#context.deallocate(pointer, bytes.byteLength);
            throw error;
        }
    }

    public readWords(pointer: number, wordCount: number): readonly number[] {
        const byteLength = wordCount * wasm32WordByteLength;
        if (
            !Number.isSafeInteger(wordCount) ||
            wordCount <= 0 ||
            pointer === 0 ||
            pointer + byteLength > this.#context.memory.buffer.byteLength
        ) {
            throw this.#createInternalError(
                `The ${this.#label} metadata range is invalid.`,
            );
        }
        const view = new DataView(
            this.#context.memory.buffer,
            pointer,
            byteLength,
        );
        return Object.freeze(
            Array.from({ length: wordCount }, (_, wordIndex) =>
                view.getUint32(wordIndex * wasm32WordByteLength, true),
            ),
        );
    }

    public zeroAndDeallocate(pointer: number, byteLength: number): void {
        if (pointer === 0) {
            return;
        }
        new Uint8Array(this.#context.memory.buffer, pointer, byteLength).fill(
            0,
        );
        this.#context.deallocate(pointer, byteLength);
    }

    public assertWithinProfile(): void {
        if (
            this.#context.memory.buffer.byteLength >
            foundationProfile.maximumWasmMemoryByteLength
        ) {
            throw this.#createResourceError(
                `The ${this.#label} WASM memory exceeds the supported profile.`,
            );
        }
    }
}
