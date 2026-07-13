import {
    openAcceptedSetupSession,
    registerAcceptedSetupSessionKernelContext,
} from '../accepted-setup-session-runtime.js';
import { registerCanonicalStreamKernelContext } from '../canonical-stream-runtime.js';
import { registerFoundationBoardKernelContext } from '../foundation-board-session.js';

import type {
    AcceptedSetupSession,
    PublishedSdkKernel,
    TranscriptCoreKernelExports,
} from './kernel-contracts.js';
import type {
    TranscriptCoreKernelCommandRuntime,
    TranscriptCoreKernelLoaderOptions,
} from './kernel-runtime.js';
import {
    instantiateTranscriptCoreKernelCommandRuntime,
    resolveNumberExport,
    runKernelCommand,
    TranscriptCoreKernelCommandError,
} from './kernel-runtime.js';

type NumberExportName = Parameters<typeof resolveNumberExport>[1];

const resolveOptionalNumberExport = <ExportName extends NumberExportName>(
    wasmExports: TranscriptCoreKernelExports,
    exportName: ExportName,
): NonNullable<TranscriptCoreKernelExports[ExportName]> | undefined =>
    typeof wasmExports[exportName] === 'function'
        ? (resolveNumberExport(wasmExports, exportName) as NonNullable<
              TranscriptCoreKernelExports[ExportName]
          >)
        : undefined;

const registerPublishedSdkKernelContexts = (
    kernel: PublishedSdkKernel,
    runtime: TranscriptCoreKernelCommandRuntime,
): void => {
    const { wasmExports } = runtime;
    const canonicalStreamAbsorbChunk = resolveOptionalNumberExport(
        wasmExports,
        'sealed_lattice_canonical_stream_absorb_chunk',
    );
    const canonicalStreamBeginVerifier = resolveOptionalNumberExport(
        wasmExports,
        'sealed_lattice_canonical_stream_begin_verifier',
    );
    const canonicalStreamBeginWriter = resolveOptionalNumberExport(
        wasmExports,
        'sealed_lattice_canonical_stream_begin_writer',
    );
    const canonicalStreamCancel = resolveOptionalNumberExport(
        wasmExports,
        'sealed_lattice_canonical_stream_cancel',
    );
    const canonicalStreamFinishVerifier = resolveOptionalNumberExport(
        wasmExports,
        'sealed_lattice_canonical_stream_finish_verifier',
    );
    const canonicalStreamFinishWriter = resolveOptionalNumberExport(
        wasmExports,
        'sealed_lattice_canonical_stream_finish_writer',
    );
    if (
        canonicalStreamAbsorbChunk !== undefined &&
        canonicalStreamBeginVerifier !== undefined &&
        canonicalStreamBeginWriter !== undefined &&
        canonicalStreamCancel !== undefined &&
        canonicalStreamFinishVerifier !== undefined &&
        canonicalStreamFinishWriter !== undefined
    ) {
        registerCanonicalStreamKernelContext(kernel, {
            absorbChunk: canonicalStreamAbsorbChunk,
            allocate: runtime.allocate,
            bgvAbsorbChunk: resolveOptionalNumberExport(
                wasmExports,
                'sealed_lattice_bgv_canonical_stream_absorb_chunk',
            ),
            bgvBegin: resolveOptionalNumberExport(
                wasmExports,
                'sealed_lattice_bgv_canonical_stream_begin',
            ),
            bgvCancel: resolveOptionalNumberExport(
                wasmExports,
                'sealed_lattice_bgv_canonical_stream_cancel',
            ),
            bgvFinish: resolveOptionalNumberExport(
                wasmExports,
                'sealed_lattice_bgv_canonical_stream_finish',
            ),
            bgvMaterialReaderBegin: resolveOptionalNumberExport(
                wasmExports,
                'sealed_lattice_bgv_canonical_material_reader_begin',
            ),
            bgvMaterialReaderCancel: resolveOptionalNumberExport(
                wasmExports,
                'sealed_lattice_bgv_canonical_material_reader_cancel',
            ),
            bgvMaterialReaderFinish: resolveOptionalNumberExport(
                wasmExports,
                'sealed_lattice_bgv_canonical_material_reader_finish',
            ),
            bgvMaterialReaderReadChunk: resolveOptionalNumberExport(
                wasmExports,
                'sealed_lattice_bgv_canonical_material_reader_read_chunk',
            ),
            beginVerifier: canonicalStreamBeginVerifier,
            beginWriter: canonicalStreamBeginWriter,
            cancel: canonicalStreamCancel,
            deallocate: runtime.deallocate,
            finishVerifier: canonicalStreamFinishVerifier,
            finishWriter: canonicalStreamFinishWriter,
            memory: runtime.memory,
            runExclusive: runtime.runExclusive,
        });
    }

    const foundationBoardBegin = resolveOptionalNumberExport(
        wasmExports,
        'sealed_lattice_foundation_board_begin',
    );
    const foundationBoardCancel = resolveOptionalNumberExport(
        wasmExports,
        'sealed_lattice_foundation_board_cancel',
    );
    const foundationBoardIngest = resolveOptionalNumberExport(
        wasmExports,
        'sealed_lattice_foundation_board_ingest',
    );
    const foundationBoardRequireCompleteCarrierGraph =
        resolveOptionalNumberExport(
            wasmExports,
            'sealed_lattice_foundation_board_require_complete_carrier_graph',
        );
    if (
        foundationBoardBegin !== undefined &&
        foundationBoardCancel !== undefined &&
        foundationBoardIngest !== undefined &&
        foundationBoardRequireCompleteCarrierGraph !== undefined
    ) {
        registerFoundationBoardKernelContext(kernel, {
            allocate: runtime.allocate,
            begin: foundationBoardBegin,
            cancel: foundationBoardCancel,
            deallocate: runtime.deallocate,
            ingest: foundationBoardIngest,
            memory: runtime.memory,
            requireCompleteCarrierGraph:
                foundationBoardRequireCompleteCarrierGraph,
            runExclusive: runtime.runExclusive,
        });
    }
};

const publishedSdkKernel = (
    runtime: TranscriptCoreKernelCommandRuntime,
): PublishedSdkKernel => {
    const acceptedSetupSessionBegin = resolveNumberExport(
        runtime.wasmExports,
        'sealed_lattice_accepted_setup_session_begin',
    ) as NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_accepted_setup_session_begin']
    >;
    const acceptedSetupSessionCancel = resolveNumberExport(
        runtime.wasmExports,
        'sealed_lattice_accepted_setup_session_cancel',
    ) as NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_accepted_setup_session_cancel']
    >;
    const acceptedSetupCanonicalStreamBegin = resolveNumberExport(
        runtime.wasmExports,
        'sealed_lattice_accepted_setup_canonical_stream_begin',
    ) as NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_accepted_setup_canonical_stream_begin']
    >;
    const acceptedSetupCommandWithLength = resolveNumberExport(
        runtime.wasmExports,
        'sealed_lattice_accepted_setup_command_with_length',
    ) as NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_accepted_setup_command_with_length']
    >;
    const translateAcceptedSetupCommandFailure = <Result>(
        operation: () => Result,
    ): Result => {
        try {
            return operation();
        } catch (error) {
            if (
                error instanceof TranscriptCoreKernelCommandError &&
                error.code === 'InvalidFixture'
            ) {
                throw new TranscriptCoreKernelCommandError({
                    code: 'InvalidProtocolObject',
                    message: error.message.replace(/^InvalidFixture: /u, ''),
                });
            }
            throw error;
        }
    };
    const kernel: PublishedSdkKernel = {
        beginAcceptedSetupSession: () => openAcceptedSetupSession(kernel),
        exportedFunctionNames: runtime.exportedFunctionNames,
        generateBgvTargetDecryptionShareProofMaterialFromLocalWitness: (
            input,
        ) =>
            runtime.executeCommand<
                ReturnType<
                    PublishedSdkKernel['generateBgvTargetDecryptionShareProofMaterialFromLocalWitness']
                >
            >({
                command:
                    'GenerateBgvTargetDecryptionShareProofMaterialFromLocalWitness',
                setupPackage: input.setupPackage,
                targetAcceptedRecord: input.targetAcceptedRecord,
                targetCiphertexts: input.targetCiphertexts,
                targetCiphertextBinding: input.targetCiphertextBinding,
                targetShareProfile: input.targetShareProfile,
                trusteeIdentity: input.trusteeIdentity,
                localTargetShareWitness: input.localTargetShareWitness,
                targetDecryptionShare: input.targetDecryptionShare,
                proofStatement: input.proofStatement,
                proofRandomnessSeedHex: input.proofRandomnessSeedHex,
                proofRandomnessNonceHex: input.proofRandomnessNonceHex,
            }),
        verifyPrivateVssShareEnvelope: (input) =>
            runtime.executeCommand<
                ReturnType<PublishedSdkKernel['verifyPrivateVssShareEnvelope']>
            >({
                command: 'VerifyPrivateVssShareEnvelope',
                setupContext: input.setupContext,
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                sourceTrusteeCoefficientCommitmentRecord:
                    input.sourceTrusteeCoefficientCommitmentRecord,
                sourceTrusteeCoefficientCommitmentMaterialRecords:
                    input.sourceTrusteeCoefficientCommitmentMaterialRecords,
                privateEnvelope: input.privateEnvelope,
                transportedPrivateVssShareProofMaterial:
                    input.transportedPrivateVssShareProofMaterial,
                expectedPrivateEnvelopeHash: input.expectedPrivateEnvelopeHash,
                expectedLocalVerificationRoot:
                    input.expectedLocalVerificationRoot,
            }),
        deriveBgvTargetDecryptionResultReleaseSetupContext: (input) =>
            runtime.executeCommand<
                ReturnType<
                    PublishedSdkKernel['deriveBgvTargetDecryptionResultReleaseSetupContext']
                >
            >({
                command: 'DeriveBgvTargetDecryptionResultReleaseSetupContext',
                setupPackage: input.setupPackage,
            }),
        beginBgvTargetDecryptionResultRelease: (input) =>
            runtime.executeCommand<
                ReturnType<
                    PublishedSdkKernel['beginBgvTargetDecryptionResultRelease']
                >
            >({
                command: 'BeginBgvTargetDecryptionResultRelease',
                releaseVerificationId: input.releaseVerificationId,
                releaseSetupContext: input.releaseSetupContext,
                targetAcceptedRecord: input.targetAcceptedRecord,
                targetCiphertexts: input.targetCiphertexts,
                targetCiphertextBinding: input.targetCiphertextBinding,
                targetShareProfile: input.targetShareProfile,
            }),
        absorbBgvTargetDecryptionResultReleaseShare: (input) =>
            runtime.executeCommand<
                ReturnType<
                    PublishedSdkKernel['absorbBgvTargetDecryptionResultReleaseShare']
                >
            >({
                command: 'AbsorbBgvTargetDecryptionResultReleaseShare',
                releaseVerificationId: input.releaseVerificationId,
                targetShareProof: input.targetShareProof,
            }),
        finishBgvTargetDecryptionResultRelease: (input) =>
            runtime.executeCommand<
                ReturnType<
                    PublishedSdkKernel['finishBgvTargetDecryptionResultRelease']
                >
            >({
                command: 'FinishBgvTargetDecryptionResultRelease',
                releaseVerificationId: input.releaseVerificationId,
            }),
    };
    registerPublishedSdkKernelContexts(kernel, runtime);
    registerAcceptedSetupSessionKernelContext(kernel, {
        allocate: runtime.allocate,
        begin: acceptedSetupSessionBegin,
        beginCanonicalStream: acceptedSetupCanonicalStreamBegin,
        cancel: acceptedSetupSessionCancel,
        deallocate: runtime.deallocate,
        executeCommand: (
            request,
            sessionHandle,
            capabilityPointer,
            capabilityLength,
            beforeKernelInvocation,
        ) =>
            translateAcceptedSetupCommandFailure(() =>
                runtime.runExclusive('accepted-setup command', () =>
                    runKernelCommand<
                        ReturnType<
                            AcceptedSetupSession['verifyCollectiveBgvSetup']
                        >
                    >(
                        runtime.memory,
                        runtime.allocate,
                        runtime.deallocate,
                        (pointer, length, outputLengthPointer) => {
                            beforeKernelInvocation();
                            return acceptedSetupCommandWithLength(
                                pointer,
                                length,
                                sessionHandle,
                                capabilityPointer,
                                capabilityLength,
                                outputLengthPointer,
                            );
                        },
                        request,
                    ),
                ),
            ),
        memory: runtime.memory,
        runExclusive: runtime.runExclusive,
    });

    return kernel;
};

export const createPublishedSdkKernelLoader = (
    transcriptCoreKernelUrl: URL,
    options: TranscriptCoreKernelLoaderOptions = {},
): (() => Promise<PublishedSdkKernel>) => {
    let kernelPromise: Promise<PublishedSdkKernel> | undefined;

    return async (): Promise<PublishedSdkKernel> => {
        kernelPromise ??= instantiateTranscriptCoreKernelCommandRuntime(
            transcriptCoreKernelUrl,
            options,
        )
            .then(publishedSdkKernel)
            .catch((error: unknown) => {
                kernelPromise = undefined;
                throw error;
            });

        return kernelPromise;
    };
};
