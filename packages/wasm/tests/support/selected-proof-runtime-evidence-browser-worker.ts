import {
    parseDesktopBrowserProofEvidenceWorkerStartMessage,
    type DesktopBrowserProofEvidenceWorkerStartMessage,
} from './selected-proof-runtime-evidence-transport.js';

import { loadFreshTranscriptCoreKernel } from '#packages/wasm/src/index';
import { resolveCommonProofKernelContext } from '#packages/wasm/src/transcript-core-bridge/common-proof-kernel-context';

const workerScope = globalThis as unknown as Readonly<{
    addEventListener(
        type: 'message',
        listener: (event: MessageEvent<unknown>) => void,
    ): void;
    postMessage(message: unknown): void;
}>;

const runSelectedProofRuntimeEvidence = async (
    message: DesktopBrowserProofEvidenceWorkerStartMessage,
): Promise<void> => {
    const kernel = await loadFreshTranscriptCoreKernel();
    const context = resolveCommonProofKernelContext(kernel);
    if (context === undefined || context.memory.buffer.byteLength === 0) {
        throw new Error(
            'The processed WebAssembly module did not expose its production common-proof runtime.',
        );
    }

    if (message.ownershipRole === 'generation') {
        throw new Error(
            'Desktop proof generation evidence is blocked because the production worker does not expose one frozen canonical suite record and the authenticated setup intent, VSS terminal, evaluator source, and package-assembly authorities required to generate genuine same-secret and relinearization-round-two proofs.',
        );
    }

    throw new Error(
        'Desktop proof verification evidence is blocked because the production worker does not expose the canonical application records and verified prerequisite authorities required to reconstruct and freshly verify the transported suite-bound same-secret and relinearization-round-two statements.',
    );
};

let started = false;
workerScope.addEventListener('message', (event) => {
    if (started) {
        workerScope.postMessage({
            failureMessage:
                'The desktop proof-evidence worker accepts exactly one role-specific operation.',
            messageKind: 'failure',
        });
        return;
    }
    started = true;
    let message: DesktopBrowserProofEvidenceWorkerStartMessage;
    try {
        message = parseDesktopBrowserProofEvidenceWorkerStartMessage(
            event.data,
        );
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
