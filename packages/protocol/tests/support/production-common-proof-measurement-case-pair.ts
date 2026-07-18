import type {
    CommonProofGenerationCheckpoint,
    CommonProofGenerationWorkerOptions,
} from '@sealed-lattice/wasm';
import { CommonProofWorkerRuntimeError } from '@sealed-lattice/wasm';

import type {
    CommonProofBrowserCustody,
    CommonProofCheckpointResumeDescriptor,
} from '#packages/protocol/src/runtime/common-proof-browser-custody';
import type {
    DesktopBrowserProofExecutionKind,
    ProductionDesktopBrowserCommonProofMeasurementCase,
} from '#packages/protocol/tests/support/desktop-browser-common-proof-measurement';
import type { ProductionDesktopBrowserMeasurementIdentity } from '#packages/protocol/tests/support/desktop-browser-production-measurement-identity';
import { createReplaceableCommonProofBrowserCustody } from '#packages/protocol/tests/support/replaceable-common-proof-browser-custody';

type ProductionCommonProofMeasurementCasePair = Readonly<{
    fresh: ProductionDesktopBrowserCommonProofMeasurementCase;
    resumed: ProductionDesktopBrowserCommonProofMeasurementCase;
}>;

export type ProductionCommonProofMeasurementOperation = Readonly<{
    close(): Promise<void>;
    initialCustody: CommonProofBrowserCustody;
    measurementIdentity: ProductionDesktopBrowserMeasurementIdentity;
    openResumedCustody(
        descriptor: CommonProofCheckpointResumeDescriptor,
    ): Promise<CommonProofBrowserCustody>;
    run(input: {
        custody: CommonProofBrowserCustody;
        generationMode: DesktopBrowserProofExecutionKind;
        generationOptions: CommonProofGenerationWorkerOptions;
    }): Promise<void>;
    wasmMemory: WebAssembly.Memory;
}>;

const destroyResumeDescriptor = (
    descriptor: CommonProofCheckpointResumeDescriptor,
): void => {
    descriptor.checkpointLineageIdentifier.fill(0);
    descriptor.commonProofEnvironmentIdentifier.fill(0);
    descriptor.privateRandomCursorManifestBytes.fill(0);
    descriptor.privateRandomnessStreamAttemptIdentifier?.fill(0);
    descriptor.stableAttemptBindingHash.fill(0);
};

const requireCheckpointCustody = (
    custody: CommonProofBrowserCustody,
): NonNullable<CommonProofBrowserCustody['checkpointCustody']> => {
    if (custody.checkpointCustody === undefined) {
        throw new Error(
            'Production common-proof resumed measurement requires checkpoint custody.',
        );
    }
    return custody.checkpointCustody;
};

const requireExpectedCheckpointCancellation = (
    failure: unknown,
    cancellationReason: Error,
): void => {
    if (
        !(failure instanceof CommonProofWorkerRuntimeError) ||
        failure.code !== 'Cancelled' ||
        failure.failureCause !== cancellationReason
    ) {
        throw failure instanceof Error
            ? failure
            : Object.assign(
                  new Error(
                      'The interrupted production common-proof attempt failed with a non-error value.',
                  ),
                  { cause: failure },
              );
    }
};

const openFreshMeasurementSession = async (
    openOperation: () => Promise<ProductionCommonProofMeasurementOperation>,
) => {
    const operation = await openOperation();
    return Object.freeze({
        close: () => operation.close(),
        custody: operation.initialCustody,
        execute: (input: {
            custody: CommonProofBrowserCustody;
            yieldControl(): Promise<void>;
        }) =>
            operation.run({
                custody: input.custody,
                generationMode: 'fresh',
                generationOptions: Object.freeze({
                    checkpointCustody: requireCheckpointCustody(input.custody),
                    yieldControl: () => input.yieldControl(),
                }),
            }),
        measurementIdentity: operation.measurementIdentity,
        wasmMemory: operation.wasmMemory,
    });
};

const openResumedMeasurementSession = async (
    openOperation: () => Promise<ProductionCommonProofMeasurementOperation>,
) => {
    const operation = await openOperation();
    const replaceableCustody = createReplaceableCommonProofBrowserCustody(
        operation.initialCustody,
    );
    return Object.freeze({
        close: () => operation.close(),
        custody: replaceableCustody.custody,
        execute: async (input: {
            custody: CommonProofBrowserCustody;
            yieldControl(): Promise<void>;
        }): Promise<void> => {
            const cancellationController = new AbortController();
            const cancellationReason = new Error(
                'The production measurement reached its authenticated resume boundary.',
            );
            let checkpointPublished = false;
            const checkpointCustody = requireCheckpointCustody(input.custody);
            let interruptedFailure: unknown;
            try {
                await operation.run({
                    custody: input.custody,
                    generationMode: 'fresh',
                    generationOptions: Object.freeze({
                        checkpointCustody: Object.freeze({
                            publishAuthenticatedCheckpoint: async (
                                checkpoint: CommonProofGenerationCheckpoint,
                            ) => {
                                await checkpointCustody.publishAuthenticatedCheckpoint(
                                    checkpoint,
                                );
                                checkpointPublished = true;
                                cancellationController.abort(
                                    cancellationReason,
                                );
                            },
                            restoreAuthenticatedCheckpointState: () =>
                                checkpointCustody.restoreAuthenticatedCheckpointState(),
                        }),
                        signal: cancellationController.signal,
                        yieldControl: () => input.yieldControl(),
                    }),
                });
            } catch (failure) {
                interruptedFailure = failure;
            }
            if (!checkpointPublished) {
                if (interruptedFailure !== undefined) {
                    throw interruptedFailure instanceof Error
                        ? interruptedFailure
                        : Object.assign(
                              new Error(
                                  'The production common-proof attempt failed with a non-error value.',
                              ),
                              { cause: interruptedFailure },
                          );
                }
                throw new Error(
                    'The production common-proof attempt completed without an authenticated resume boundary.',
                );
            }
            requireExpectedCheckpointCancellation(
                interruptedFailure,
                cancellationReason,
            );

            const resumeDescriptor =
                input.custody.copyCheckpointResumeDescriptor();
            if (resumeDescriptor === undefined) {
                throw new Error(
                    'The production common-proof custody did not expose its authenticated resume descriptor.',
                );
            }
            await input.custody.suspendForAuthenticatedResume();
            let resumedCustody: CommonProofBrowserCustody;
            try {
                resumedCustody =
                    await operation.openResumedCustody(resumeDescriptor);
            } finally {
                destroyResumeDescriptor(resumeDescriptor);
            }
            replaceableCustody.replaceAfterAuthenticatedSuspension(
                resumedCustody,
            );
            const resumedCheckpointCustody = requireCheckpointCustody(
                input.custody,
            );
            await operation.run({
                custody: input.custody,
                generationMode: 'resumed',
                generationOptions: Object.freeze({
                    checkpointCustody: resumedCheckpointCustody,
                    resume: Object.freeze({
                        checkpointCustody: resumedCheckpointCustody,
                        prefixReplayExternalMemory:
                            input.custody.prefixReplayExternalMemory,
                    }),
                    yieldControl: () => input.yieldControl(),
                }),
            });
        },
        measurementIdentity: operation.measurementIdentity,
        wasmMemory: operation.wasmMemory,
    });
};

export const createProductionCommonProofMeasurementCasePair = (input: {
    freshCaseIdentifier: string;
    openOperation: () => Promise<ProductionCommonProofMeasurementOperation>;
    resumedCaseIdentifier: string;
}): ProductionCommonProofMeasurementCasePair =>
    Object.freeze({
        fresh: Object.freeze({
            caseIdentifier: input.freshCaseIdentifier,
            executionKind: 'fresh',
            open: () =>
                openFreshMeasurementSession(() => input.openOperation()),
        }),
        resumed: Object.freeze({
            caseIdentifier: input.resumedCaseIdentifier,
            executionKind: 'resumed',
            open: () =>
                openResumedMeasurementSession(() => input.openOperation()),
        }),
    });
