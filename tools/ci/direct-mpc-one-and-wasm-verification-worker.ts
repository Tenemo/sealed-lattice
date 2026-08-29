import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Worker } from 'node:worker_threads';

import {
    buildOptimizedWasmKernelArtifact,
    resolveWasmCargoExecutable,
} from './build-wasm-kernel.js';
import { resolveDirectMpcOneAndWasmVerification } from './direct-mpc-one-and-wasm-verification-registry.js';

const repoRoot = path.resolve(
    fileURLToPath(new URL('../../', import.meta.url)),
);
const workerThreadFilePath = fileURLToPath(
    new URL(
        './direct-mpc-one-and-wasm-verification-thread.ts',
        import.meta.url,
    ),
);
const temporaryRoot = path.resolve(
    repoRoot,
    'temp',
    'build-scratch',
    'direct-mpc-one-and-wasm-verification',
);
const wasmCargoTargetDirectory = path.resolve(
    repoRoot,
    'target',
    'wasm-direct-mpc-one-and-verification',
);
const nativeCargoTargetDirectory = path.resolve(
    repoRoot,
    'target',
    'native-direct-mpc-one-and-verification',
);
const exactFixtureTest =
    'pre_evaluation_finality::direct_mpc_one_and::tests::canonical_bundle_matches_the_positive_verifier_and_typed_refusal';

type ParsedArguments = Readonly<{
    outputFilePath: string;
    verificationId: string;
}>;

type ReadyMessage = Readonly<{
    exportNames: readonly string[];
    initialLinearMemoryByteLength: number;
    type: 'ready';
}>;

type ResponseMessage = Readonly<{
    durationMilliseconds: number;
    linearMemoryAfterByteLength: number;
    linearMemoryBeforeByteLength: number;
    requestByteLength: number;
    requestId: number;
    responseBytes: Uint8Array;
    type: 'response';
}>;

type ErrorMessage = Readonly<{
    error: string;
    requestId: number;
    type: 'error';
}>;

type WorkerMessage = ReadyMessage | ResponseMessage | ErrorMessage;

const parseArguments = (
    commandArguments: readonly string[],
): ParsedArguments => {
    let outputFilePath: string | undefined;
    let verificationId: string | undefined;
    for (
        let argumentPosition = 0;
        argumentPosition < commandArguments.length;
    ) {
        const argument = commandArguments[argumentPosition];
        const value = commandArguments[argumentPosition + 1];
        if (argument === '--output' && value !== undefined) {
            outputFilePath = value;
            argumentPosition += 2;
            continue;
        }
        if (argument === '--verification' && value !== undefined) {
            verificationId = value;
            argumentPosition += 2;
            continue;
        }
        throw new Error(
            `Unknown or incomplete direct-MPC one-AND verification worker argument: ${argument ?? '<missing>'}.`,
        );
    }
    if (
        outputFilePath === undefined ||
        outputFilePath.length === 0 ||
        !path.isAbsolute(outputFilePath)
    ) {
        throw new Error(
            'The direct-MPC one-AND verification worker requires an absolute --output path.',
        );
    }
    if (verificationId === undefined || verificationId.length === 0) {
        throw new Error(
            'The direct-MPC one-AND verification worker requires --verification.',
        );
    }
    return { outputFilePath, verificationId };
};

const generateNativeFixture = (fixtureDirectoryPath: string): void => {
    const environment = { ...process.env };
    delete environment.CARGO_ENCODED_RUSTFLAGS;
    environment.CARGO_BUILD_JOBS = '1';
    environment.CARGO_INCREMENTAL = '0';
    environment.CARGO_TARGET_DIR = nativeCargoTargetDirectory;
    environment.SEALED_LATTICE_DIRECT_MPC_ONE_AND_FIXTURE_DIRECTORY =
        fixtureDirectoryPath;
    const result = spawnSync(
        resolveWasmCargoExecutable(environment),
        [
            'test',
            '--locked',
            '--quiet',
            '--package',
            'sealed-lattice-kernel',
            '--features',
            'direct-mpc-one-and-verifier',
            '--lib',
            exactFixtureTest,
            '--',
            '--exact',
        ],
        {
            cwd: repoRoot,
            encoding: 'utf8',
            env: environment,
            maxBuffer: 20 * 1024 * 1024,
        },
    );
    if (result.error !== undefined) {
        throw new Error(
            `Failed to start the native direct-MPC one-AND fixture verifier: ${result.error.message}`,
        );
    }
    if (result.status !== 0) {
        throw new Error(
            `Native direct-MPC one-AND fixture verification failed with status ${result.status ?? 'null'}: ${result.stderr.trim()}`,
        );
    }
};

const awaitWorkerMessage = <Message extends WorkerMessage>(
    worker: Worker,
    predicate: (message: WorkerMessage) => message is Message,
): Promise<Message> =>
    new Promise((resolve, reject) => {
        const onMessage = (message: WorkerMessage): void => {
            if (!predicate(message)) return;
            cleanup();
            resolve(message);
        };
        const onError = (error: Error): void => {
            cleanup();
            reject(error);
        };
        const onExit = (exitCode: number): void => {
            cleanup();
            reject(
                new Error(
                    `The direct-MPC one-AND verifier worker exited early with code ${exitCode}.`,
                ),
            );
        };
        const cleanup = (): void => {
            worker.off('message', onMessage);
            worker.off('error', onError);
            worker.off('exit', onExit);
        };
        worker.on('message', onMessage);
        worker.once('error', onError);
        worker.once('exit', onExit);
    });

const verifyInWorker = async (
    worker: Worker,
    requestId: number,
    requestBytes: Uint8Array,
): Promise<ResponseMessage> => {
    const transferredRequest = Uint8Array.from(requestBytes);
    const responsePromise = awaitWorkerMessage(
        worker,
        (message): message is ResponseMessage | ErrorMessage =>
            (message.type === 'response' || message.type === 'error') &&
            message.requestId === requestId,
    );
    worker.postMessage(
        {
            requestBytes: transferredRequest,
            requestId,
            type: 'verify',
        },
        [transferredRequest.buffer],
    );
    if (transferredRequest.byteLength !== 0) {
        throw new Error(
            'The direct-MPC one-AND request did not cross a transferable worker boundary.',
        );
    }
    const response = await responsePromise;
    if (response.type === 'error') {
        throw new Error(response.error);
    }
    return response;
};

const sha3_512Hex = (bytes: Uint8Array): string =>
    createHash('sha3-512').update(bytes).digest('hex');

export const runDirectMpcOneAndWasmVerificationWorker = async (
    rawArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    const parsedArguments = parseArguments(rawArguments);
    const verification = resolveDirectMpcOneAndWasmVerification(
        parsedArguments.verificationId,
    );
    await mkdir(temporaryRoot, { recursive: true });
    const temporaryDirectoryPath = await mkdtemp(
        path.join(temporaryRoot, 'run-'),
    );
    try {
        const fixtureDirectoryPath = path.join(
            temporaryDirectoryPath,
            'fixture',
        );
        generateNativeFixture(fixtureDirectoryPath);
        const [request, nativeResponse, hostileRequest, nativeHostileResponse] =
            await Promise.all(
                [
                    'request.bin',
                    'response.bin',
                    'hostile-request.bin',
                    'hostile-response.bin',
                ].map((fileName) =>
                    readFile(path.join(fixtureDirectoryPath, fileName)),
                ),
            );
        if (
            request.byteLength > verification.maximumRequestByteLength ||
            hostileRequest.byteLength > verification.maximumRequestByteLength
        ) {
            throw new Error(
                'The direct-MPC one-AND fixture exceeds the absolute copied-buffer bound.',
            );
        }

        const wasmFilePath = path.join(temporaryDirectoryPath, 'kernel.wasm');
        const builtArtifact = await buildOptimizedWasmKernelArtifact({
            artifactLabel: 'Direct-MPC one-AND verifier kernel',
            cargoFeatures: ['direct-mpc-one-and-verifier'],
            outputFilePath: wasmFilePath,
            scratchDirectoryPrefix: 'direct-mpc-one-and-verification-',
            targetDirectoryPath: wasmCargoTargetDirectory,
        });
        const wasmBytes = await readFile(wasmFilePath);
        const worker = new Worker(workerThreadFilePath, {
            execArgv: ['--import', 'tsx'],
            workerData: {
                maximumRequestByteLength: verification.maximumRequestByteLength,
                maximumResponseByteLength:
                    verification.maximumResponseByteLength,
                maximumWasmMemoryByteLength:
                    verification.maximumWasmMemoryByteLength,
                wasmFilePath,
            },
        });
        try {
            const ready = await awaitWorkerMessage(
                worker,
                (message): message is ReadyMessage => message.type === 'ready',
            );
            if (
                !ready.exportNames.includes(
                    'sealed_lattice_verify_direct_mpc_one_and_with_length',
                )
            ) {
                throw new Error(
                    'The scalar worker did not expose the direct-MPC one-AND positive verifier.',
                );
            }
            const positive = await verifyInWorker(worker, 1, request);
            const repeatedPositive = await verifyInWorker(worker, 2, request);
            const hostile = await verifyInWorker(worker, 3, hostileRequest);
            if (
                !Buffer.from(positive.responseBytes).equals(nativeResponse) ||
                !Buffer.from(repeatedPositive.responseBytes).equals(
                    nativeResponse,
                ) ||
                !Buffer.from(hostile.responseBytes).equals(
                    nativeHostileResponse,
                )
            ) {
                throw new Error(
                    'Rust and scalar WebAssembly direct-MPC one-AND verifier bytes differ.',
                );
            }
            const maximumVerificationDurationMilliseconds = Math.max(
                positive.durationMilliseconds,
                repeatedPositive.durationMilliseconds,
                hostile.durationMilliseconds,
            );
            if (
                maximumVerificationDurationMilliseconds >
                verification.maximumVerificationMilliseconds
            ) {
                throw new Error(
                    `The direct-MPC one-AND verifier took ${maximumVerificationDurationMilliseconds} ms; the absolute result-verification target is ${verification.maximumVerificationMilliseconds} ms.`,
                );
            }
            const maximumLinearMemoryByteLength = Math.max(
                ready.initialLinearMemoryByteLength,
                positive.linearMemoryAfterByteLength,
                repeatedPositive.linearMemoryAfterByteLength,
                hostile.linearMemoryAfterByteLength,
            );
            const result = Object.freeze({
                evidenceClassification: verification.evidenceClassification,
                hostile: Object.freeze({
                    durationMilliseconds: hostile.durationMilliseconds,
                    requestByteLength: hostileRequest.byteLength,
                    responseByteLength: hostile.responseBytes.byteLength,
                    responseSha3_512Hex: sha3_512Hex(hostile.responseBytes),
                    rustAndWasmByteIdentical: true,
                }),
                maximumCopiedInputByteLength:
                    verification.maximumRequestByteLength,
                maximumLinearMemoryByteLength,
                maximumVerificationDurationMilliseconds,
                positive: Object.freeze({
                    durationMilliseconds: positive.durationMilliseconds,
                    repeatedDurationMilliseconds:
                        repeatedPositive.durationMilliseconds,
                    requestByteLength: request.byteLength,
                    responseByteLength: positive.responseBytes.byteLength,
                    responseSha3_512Hex: sha3_512Hex(positive.responseBytes),
                    repeatedResponseByteIdentical: true,
                    rustAndWasmByteIdentical: true,
                }),
                scalarOnly: true,
                schemaVersion: 1,
                verificationId: verification.verificationId,
                wasmByteLength: wasmBytes.byteLength,
                wasmNormalizedSha256Hex: builtArtifact.normalizedSha256Hex,
                workerCount: 1,
            });
            await mkdir(path.dirname(parsedArguments.outputFilePath), {
                recursive: true,
            });
            await writeFile(
                parsedArguments.outputFilePath,
                `${JSON.stringify(result, null, 2)}\n`,
                'utf8',
            );
            console.log(JSON.stringify(result));
        } finally {
            worker.postMessage({ type: 'close' });
            await worker.terminate();
        }
    } finally {
        await rm(temporaryDirectoryPath, { force: true, recursive: true });
    }
};

if (import.meta.main) {
    await runDirectMpcOneAndWasmVerificationWorker();
}
