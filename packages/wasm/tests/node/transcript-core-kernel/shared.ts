import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { afterEach, vi } from 'vitest';

import {
    createTranscriptCoreKernelLoader,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/transcript-core-bridge';

const cloneJsonValue = <JsonValue>(value: JsonValue): JsonValue =>
    JSON.parse(JSON.stringify(value)) as JsonValue;

const singleZeroByteSha256Hex =
    '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d';

const textEncoder = new TextEncoder();

const textDecoder = new TextDecoder();

const wasmHeader = Uint8Array.from([0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0]);

const createMockKernelExports = ({
    allocationPointer = 12,
    commandPointer = 128,
    commandResponse = {
        success: true,
        value: {
            hash512: 'feedface',
        },
    },
    allowUnpinnedKernel = false,
    expectedKernelSha256Hex = singleZeroByteSha256Hex,
    onCommand,
    outputLengthAllocationPointer = 512,
}: {
    readonly allowUnpinnedKernel?: boolean;
    readonly allocationPointer?: number;
    readonly commandPointer?: number;
    readonly commandResponse?: unknown;
    readonly expectedKernelSha256Hex?: string;
    readonly onCommand?: (command: unknown) => void;
    readonly outputLengthAllocationPointer?: number;
} = {}): {
    readonly deallocate: ReturnType<typeof vi.fn>;
    readonly encodedCommandResponseLength: number;
    readonly getInstantiateCallCount: () => number;
    readonly loadMockKernel: () => Promise<TranscriptCoreKernel>;
    readonly rejectNextInstantiation: (error: Error) => void;
} => {
    const encodedCommandResponse = new TextEncoder().encode(
        JSON.stringify(commandResponse),
    );
    const deallocate = vi.fn();
    const memory = new WebAssembly.Memory({ initial: 1 });
    const allocationPointers = [
        allocationPointer,
        outputLengthAllocationPointer,
    ];
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
                memory,
                sealed_lattice_accepted_setup_canonical_stream_begin: vi.fn(
                    () => 1,
                ),
                sealed_lattice_accepted_setup_command_with_length: vi.fn(
                    (
                        pointer: number,
                        length: number,
                        _sessionHandle: number,
                        _capabilityPointer: number,
                        _capabilityLength: number,
                        outputLengthPointer: number,
                    ) => {
                        const encodedCommand = new Uint8Array(
                            memory.buffer,
                            pointer,
                            length,
                        );
                        onCommand?.(
                            JSON.parse(textDecoder.decode(encodedCommand)),
                        );
                        new Uint8Array(memory.buffer).set(
                            encodedCommandResponse,
                            commandPointer,
                        );
                        new DataView(memory.buffer).setUint32(
                            outputLengthPointer,
                            encodedCommandResponse.length,
                            true,
                        );
                        return commandPointer;
                    },
                ),
                sealed_lattice_accepted_setup_session_begin: vi.fn(() => 1),
                sealed_lattice_accepted_setup_session_cancel: vi.fn(() => 0),
                sealed_lattice_allocate: vi.fn(
                    () => allocationPointers.shift() ?? allocationPointer,
                ),
                sealed_lattice_deallocate: deallocate,
                sealed_lattice_transcript_core_command_with_length: vi.fn(
                    (
                        pointer: number,
                        length: number,
                        outputLengthPointer: number,
                    ) => {
                        const encodedCommand = new Uint8Array(
                            memory.buffer,
                            pointer,
                            length,
                        );
                        onCommand?.(
                            JSON.parse(textDecoder.decode(encodedCommand)),
                        );
                        new Uint8Array(memory.buffer).set(
                            encodedCommandResponse,
                            commandPointer,
                        );
                        new DataView(memory.buffer).setUint32(
                            outputLengthPointer,
                            encodedCommandResponse.length,
                            true,
                        );

                        return commandPointer;
                    },
                ),
            },
        },
        module: fakeModule,
    };

    vi.mocked(readFile).mockResolvedValue(Buffer.from([0]));
    const instantiate = vi
        .spyOn(webAssemblyWithByteSourceInstantiate, 'instantiate')
        .mockResolvedValue(instantiatedSource);
    vi.spyOn(WebAssembly.Module, 'exports').mockReturnValue([
        { kind: 'memory', name: 'memory' },
        {
            kind: 'function',
            name: 'sealed_lattice_accepted_setup_canonical_stream_begin',
        },
        {
            kind: 'function',
            name: 'sealed_lattice_accepted_setup_command_with_length',
        },
        {
            kind: 'function',
            name: 'sealed_lattice_accepted_setup_session_begin',
        },
        {
            kind: 'function',
            name: 'sealed_lattice_accepted_setup_session_cancel',
        },
        { kind: 'function', name: 'sealed_lattice_allocate' },
        { kind: 'function', name: 'sealed_lattice_deallocate' },
        {
            kind: 'function',
            name: 'sealed_lattice_transcript_core_command_with_length',
        },
    ]);

    return {
        deallocate,
        encodedCommandResponseLength: encodedCommandResponse.length,
        getInstantiateCallCount: () => instantiate.mock.calls.length,
        loadMockKernel: createTranscriptCoreKernelLoader(
            pathToFileURL(path.resolve('mock-sealed-lattice-kernel.wasm')),
            allowUnpinnedKernel
                ? { allowUnpinnedKernel: true }
                : { expectedKernelSha256Hex },
        ),
        rejectNextInstantiation: (error: Error): void => {
            instantiate.mockRejectedValueOnce(error);
        },
    };
};

vi.mock('node:fs/promises', async (importOriginal) => {
    const actual = await importOriginal<typeof import('node:fs/promises')>();

    return {
        ...actual,
        readFile: vi.fn(actual.readFile),
    };
});

afterEach(() => {
    vi.restoreAllMocks();
});

export {
    cloneJsonValue,
    textEncoder,
    textDecoder,
    wasmHeader,
    createMockKernelExports,
};
