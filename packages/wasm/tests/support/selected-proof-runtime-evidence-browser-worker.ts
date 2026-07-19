import { loadFreshTranscriptCoreKernel } from '#packages/wasm/src/index';
import { resolveCommonProofKernelContext } from '#packages/wasm/src/transcript-core-bridge/common-proof-kernel-context';

type StartMessage = Readonly<{
    command: 'run-selected-proof-runtime-evidence';
    wasmSha256Hex: string;
}>;

const workerScope = globalThis as unknown as Readonly<{
    addEventListener(
        type: 'message',
        listener: (event: MessageEvent<unknown>) => void,
    ): void;
    postMessage(message: unknown): void;
}>;

const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

const parseStartMessage = (value: unknown): StartMessage => {
    if (
        !isRecord(value) ||
        value.command !== 'run-selected-proof-runtime-evidence' ||
        typeof value.wasmSha256Hex !== 'string' ||
        !/^[0-9a-f]{64}$/u.test(value.wasmSha256Hex)
    ) {
        throw new TypeError(
            'The desktop proof-evidence worker received a malformed start message.',
        );
    }
    return Object.freeze({
        command: value.command,
        wasmSha256Hex: value.wasmSha256Hex,
    });
};

const runSelectedProofRuntimeEvidence = async (
    _message: StartMessage,
): Promise<void> => {
    const kernel = await loadFreshTranscriptCoreKernel();
    const context = resolveCommonProofKernelContext(kernel);
    if (context === undefined || context.memory.buffer.byteLength === 0) {
        throw new Error(
            'The processed WebAssembly module did not expose its production common-proof runtime.',
        );
    }

    // The production kernel intentionally refuses every selected proof until
    // one exact suite record and its six real artifact references are frozen.
    // The evidence workload must consume that record and construct genuine
    // setup, ballot, aggregate, and replay authorities; a synthetic suite or
    // fixture acknowledgement is not an evidence substitute.
    throw new Error(
        'Desktop proof evidence is blocked until the production kernel freezes and exposes the exact selected suite record with its six real artifact references.',
    );
};

let started = false;
workerScope.addEventListener('message', (event) => {
    if (started) {
        workerScope.postMessage({
            failureMessage:
                'The desktop proof-evidence worker accepts exactly one workload.',
            messageKind: 'failure',
        });
        return;
    }
    started = true;
    let message: StartMessage;
    try {
        message = parseStartMessage(event.data);
    } catch (error) {
        workerScope.postMessage({
            failureMessage:
                error instanceof Error
                    ? error.message
                    : 'The desktop proof-evidence start message was rejected.',
            messageKind: 'failure',
        });
        return;
    }
    void runSelectedProofRuntimeEvidence(message)
        .then(() => workerScope.postMessage({ messageKind: 'complete' }))
        .catch((error: unknown) => {
            workerScope.postMessage({
                failureMessage:
                    error instanceof Error
                        ? error.message
                        : 'The desktop proof-evidence workload failed.',
                messageKind: 'failure',
            });
        });
});
