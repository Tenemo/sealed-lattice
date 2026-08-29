import { readFile } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
import { parentPort, workerData } from 'node:worker_threads';

type WorkerConfiguration = Readonly<{
    maximumDirectRequestByteLength: number;
    maximumDirectResponseByteLength: number;
    maximumSourceStateRequestByteLength: number;
    maximumSourceStateResponseByteLength: number;
    maximumWasmMemoryByteLength: number;
    wasmFilePath: string;
}>;

type VerificationRequest = Readonly<{
    operation: 'one-and' | 'source-state';
    requestBytes: Uint8Array;
    requestId: number;
    type: 'verify';
}>;

type CloseRequest = Readonly<{ type: 'close' }>;

type DirectMpcOneAndExports = Readonly<{
    allocate: (byteLength: number) => number;
    deallocate: (pointer: number, byteLength: number) => void;
    deallocateSecret: (pointer: number, byteLength: number) => void;
    memory: WebAssembly.Memory;
    verify: (
        pointer: number,
        byteLength: number,
        outputLengthPointer: number,
    ) => number;
    verifySourceState: (
        pointer: number,
        byteLength: number,
        outputLengthPointer: number,
    ) => number;
}>;

const configuration = workerData as WorkerConfiguration;
const messagePort = parentPort;
if (messagePort === null) {
    throw new Error(
        'The direct-MPC one-AND verifier must run inside a worker thread.',
    );
}

const resolveFunction = <FunctionType>(
    exports: WebAssembly.Exports,
    exportName: string,
): FunctionType => {
    const value = exports[exportName];
    if (typeof value !== 'function') {
        throw new Error(
            `The direct-MPC one-AND WebAssembly build does not export ${exportName}.`,
        );
    }
    return value as unknown as FunctionType;
};

const wasmBytes = await readFile(configuration.wasmFilePath);
const copiedWasmBytes = Uint8Array.from(wasmBytes);
const module = await WebAssembly.compile(copiedWasmBytes.buffer);
const instance = await WebAssembly.instantiate(module, {});
const memory = instance.exports.memory;
if (!(memory instanceof WebAssembly.Memory)) {
    throw new Error(
        'The direct-MPC one-AND WebAssembly build does not export linear memory.',
    );
}
const exports: DirectMpcOneAndExports = Object.freeze({
    allocate: resolveFunction<(byteLength: number) => number>(
        instance.exports,
        'sealed_lattice_allocate',
    ),
    deallocate: resolveFunction<(pointer: number, byteLength: number) => void>(
        instance.exports,
        'sealed_lattice_deallocate',
    ),
    deallocateSecret: resolveFunction<
        (pointer: number, byteLength: number) => void
    >(instance.exports, 'sealed_lattice_deallocate_secret'),
    memory,
    verify: resolveFunction<
        (
            pointer: number,
            byteLength: number,
            outputLengthPointer: number,
        ) => number
    >(instance.exports, 'sealed_lattice_verify_direct_mpc_one_and_with_length'),
    verifySourceState: resolveFunction<
        (
            pointer: number,
            byteLength: number,
            outputLengthPointer: number,
        ) => number
    >(
        instance.exports,
        'sealed_lattice_direct_mpc_preprocessing_source_state_with_length',
    ),
});

let verificationInProgress = false;

const verify = (request: VerificationRequest) => {
    if (verificationInProgress) {
        throw new Error(
            'The direct-MPC one-AND worker refuses overlapping verifier operations.',
        );
    }
    const maximumRequestByteLength =
        request.operation === 'one-and'
            ? configuration.maximumDirectRequestByteLength
            : configuration.maximumSourceStateRequestByteLength;
    const maximumResponseByteLength =
        request.operation === 'one-and'
            ? configuration.maximumDirectResponseByteLength
            : configuration.maximumSourceStateResponseByteLength;
    if (
        !Number.isSafeInteger(request.requestId) ||
        request.requestId < 0 ||
        request.requestBytes.byteLength === 0 ||
        request.requestBytes.byteLength > maximumRequestByteLength
    ) {
        throw new Error(
            'The direct-MPC one-AND worker received an invalid request boundary.',
        );
    }

    verificationInProgress = true;
    const requestByteLength = request.requestBytes.byteLength;
    let inputPointer = 0;
    let outputLengthPointer = 0;
    let outputPointer = 0;
    let outputByteLength = 0;
    try {
        inputPointer = exports.allocate(requestByteLength) >>> 0;
        outputLengthPointer = exports.allocate(4) >>> 0;
        if (inputPointer === 0 || outputLengthPointer === 0) {
            throw new Error(
                'The direct-MPC one-AND worker could not allocate verifier input.',
            );
        }
        new Uint8Array(
            exports.memory.buffer,
            inputPointer,
            requestByteLength,
        ).set(request.requestBytes);
        new DataView(exports.memory.buffer).setUint32(
            outputLengthPointer,
            0,
            true,
        );
        const linearMemoryBeforeByteLength = exports.memory.buffer.byteLength;
        const startedAt = performance.now();
        const operation =
            request.operation === 'one-and'
                ? exports.verify
                : exports.verifySourceState;
        outputPointer =
            operation(inputPointer, requestByteLength, outputLengthPointer) >>>
            0;
        const durationMilliseconds = performance.now() - startedAt;
        outputByteLength = new DataView(exports.memory.buffer).getUint32(
            outputLengthPointer,
            true,
        );
        const linearMemoryAfterByteLength = exports.memory.buffer.byteLength;
        if (
            linearMemoryAfterByteLength >
                configuration.maximumWasmMemoryByteLength ||
            outputByteLength === 0 ||
            outputByteLength > maximumResponseByteLength ||
            outputPointer === 0 ||
            outputPointer + outputByteLength > linearMemoryAfterByteLength
        ) {
            throw new Error(
                'The direct-MPC one-AND verifier exceeded an absolute memory or response bound.',
            );
        }
        const responseBytes = new Uint8Array(
            exports.memory.buffer,
            outputPointer,
            outputByteLength,
        ).slice();
        messagePort.postMessage(
            {
                durationMilliseconds,
                linearMemoryAfterByteLength,
                linearMemoryBeforeByteLength,
                requestByteLength,
                requestId: request.requestId,
                responseBytes,
                type: 'response',
            },
            [responseBytes.buffer],
        );
    } finally {
        const deallocateOperationBytes =
            request.operation === 'source-state'
                ? exports.deallocateSecret
                : exports.deallocate;
        if (outputPointer !== 0) {
            deallocateOperationBytes(outputPointer, outputByteLength);
        }
        if (inputPointer !== 0) {
            deallocateOperationBytes(inputPointer, requestByteLength);
        }
        if (outputLengthPointer !== 0) {
            exports.deallocate(outputLengthPointer, 4);
        }
        verificationInProgress = false;
    }
};

messagePort.on(
    'message',
    (message: VerificationRequest | CloseRequest): void => {
        if (message.type === 'close') {
            messagePort.close();
            return;
        }
        try {
            verify(message);
        } catch (error) {
            messagePort.postMessage({
                error:
                    error instanceof Error
                        ? error.message
                        : 'Unknown worker verification failure.',
                requestId: message.requestId,
                type: 'error',
            });
        }
    },
);

messagePort.postMessage({
    exportNames: Object.keys(instance.exports).sort(),
    initialLinearMemoryByteLength: memory.buffer.byteLength,
    type: 'ready',
});
