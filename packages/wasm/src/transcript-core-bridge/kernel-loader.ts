import type { ProtocolHash } from '@sealed-lattice/types';

import { registerCanonicalBoardKernelContext } from '../canonical-board-runtime.js';
import { registerFinalityVerifierKernelContext } from '../finality-verifier-runtime.js';
import { registerStateVerifierKernelContext } from '../state-verifier-runtime.js';

import type {
    BgvCollectiveSetupParametersDescription,
    BgvRnsParametersDescription,
    DecodedMailboxAssociatedData,
    DecodedMailboxKeyScheduleInput,
    DecodedPrivateRandomCursor,
    DecodedSignedMailboxEnvelope,
    DecodedStreamDescriptor,
    EncodedMailboxAssociatedData,
    EncodedMailboxKeyScheduleInput,
    EncodedPrivateRandomCursor,
    EncodedSignedMailboxEnvelope,
    EncodedStreamDescriptor,
    TranscriptCoreKernel,
} from './kernel-contracts.js';
import type { TranscriptCoreKernelLoaderOptions } from './kernel-runtime.js';
import {
    instantiateTranscriptCoreKernelCommandRuntime,
    resolveOptionalNumberExport,
} from './kernel-runtime.js';
import { registerLocalStorageRootKernelContext } from './local-storage-root-kernel-context.js';
import {
    createCachedKernelLoader,
    createPublishedSdkKernelBindings,
} from './published-sdk-kernel-loader.js';
import { registerPrivateKernelContexts } from './register-private-kernel-contexts.js';

export const createTranscriptCoreKernelLoader = (
    transcriptCoreKernelUrl: URL,
    options: TranscriptCoreKernelLoaderOptions = {},
): (() => Promise<TranscriptCoreKernel>) =>
    createCachedKernelLoader(async (): Promise<TranscriptCoreKernel> => {
        const runtime = await instantiateTranscriptCoreKernelCommandRuntime(
            transcriptCoreKernelUrl,
            options,
        );
        const {
            allocate,
            deallocate,
            executeCommand,
            memory,
            runExclusive: runExclusiveKernelOperation,
            wasmExports: exports,
        } = runtime;
        const localStorageRootCommand = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_local_storage_root_command',
        );
        const boardVerifierBegin = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_board_verifier_begin',
        );
        const boardVerifierCachedCarrierLength = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_board_verifier_cached_carrier_length',
        );
        const boardVerifierCancel = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_board_verifier_cancel',
        );
        const boardVerifierCopyCachedCarrier = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_board_verifier_copy_cached_carrier',
        );
        const boardVerifierDescribe = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_board_verifier_describe',
        );
        const boardVerifierRelease = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_board_verifier_release',
        );
        const boardVerifierVerifyUnordered = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_board_verifier_verify_unordered',
        );
        const finalityVerifierBegin = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_finality_verifier_begin',
        );
        const finalityVerifierCancel = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_finality_verifier_cancel',
        );
        const finalityVerifierDescribe = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_finality_verifier_describe',
        );
        const finalityVerifierRelease = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_finality_verifier_release',
        );
        const finalityVerifierVerify = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_finality_verifier_verify',
        );
        const stateVerifierBegin = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_state_verifier_begin',
        );
        const stateVerifierCancel = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_state_verifier_cancel',
        );
        const stateVerifierCertifyIntent = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_state_verifier_certify_intent',
        );
        const stateVerifierCertifyUnorderedVotes = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_state_verifier_certify_unordered_votes',
        );
        const stateVerifierDescribe = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_state_verifier_describe',
        );
        const stateVerifierRelease = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_state_verifier_release',
        );
        const stateVerifierFinishOutput = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_state_verifier_finish_output',
        );
        const stateVerifierPrepareOutput = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_state_verifier_prepare_output',
        );
        const stateVerifierPrepareReservation = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_state_verifier_prepare_reservation',
        );
        const stateProducerCommand = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_state_producer_command',
        );
        const stateVerifierVerifyReservation = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_state_verifier_verify_reservation',
        );
        const kernel: TranscriptCoreKernel = {
            ...createPublishedSdkKernelBindings(runtime),
            deriveCanonicalObjectHash: (input): ProtocolHash =>
                executeCommand<{
                    readonly canonicalObjectHash: ProtocolHash;
                }>({
                    command: 'DeriveCanonicalObjectHash',
                    value: input.value,
                }).canonicalObjectHash,
            encodeMailboxKeyScheduleInput: (input) =>
                executeCommand<EncodedMailboxKeyScheduleInput>({
                    command: 'EncodeMailboxKeyScheduleInput',
                    kemCiphertextHex: input.kemCiphertextHex,
                    value: input.value,
                }),
            decodeMailboxKeyScheduleInput: (input) =>
                executeCommand<DecodedMailboxKeyScheduleInput>({
                    command: 'DecodeMailboxKeyScheduleInput',
                    canonicalBytesHex: input.canonicalBytesHex,
                }),
            encodeMailboxAssociatedData: (value) =>
                executeCommand<EncodedMailboxAssociatedData>({
                    command: 'EncodeMailboxAssociatedData',
                    value,
                }),
            decodeMailboxAssociatedData: (input) =>
                executeCommand<DecodedMailboxAssociatedData>({
                    command: 'DecodeMailboxAssociatedData',
                    canonicalBytesHex: input.canonicalBytesHex,
                }),
            encodeStreamDescriptor: (value) =>
                executeCommand<EncodedStreamDescriptor>({
                    command: 'EncodeStreamDescriptor',
                    value,
                }),
            decodeStreamDescriptor: (input) =>
                executeCommand<DecodedStreamDescriptor>({
                    command: 'DecodeStreamDescriptor',
                    canonicalBytesHex: input.canonicalBytesHex,
                }),
            deriveSetupMailboxSlotHash: (value): ProtocolHash =>
                executeCommand<{
                    readonly setupMailboxSlotHash: ProtocolHash;
                }>({
                    command: 'DeriveSetupMailboxSlotHash',
                    value,
                }).setupMailboxSlotHash,
            encodePrivateRandomCursor: (value) =>
                executeCommand<EncodedPrivateRandomCursor>({
                    command: 'EncodePrivateRandomCursor',
                    value,
                }),
            decodePrivateRandomCursor: (input) =>
                executeCommand<DecodedPrivateRandomCursor>({
                    command: 'DecodePrivateRandomCursor',
                    canonicalBytesHex: input.canonicalBytesHex,
                }),
            encodeSignedMailboxEnvelope: (value) =>
                executeCommand<EncodedSignedMailboxEnvelope>({
                    command: 'EncodeSignedMailboxEnvelope',
                    value,
                }),
            decodeSignedMailboxEnvelope: (input) =>
                executeCommand<DecodedSignedMailboxEnvelope>({
                    command: 'DecodeSignedMailboxEnvelope',
                    canonicalBytesHex: input.canonicalBytesHex,
                }),
            deriveMailboxEnvelopeHash: (value): ProtocolHash =>
                executeCommand<{
                    readonly envelopeHash: ProtocolHash;
                }>({
                    command: 'DeriveMailboxEnvelopeHash',
                    value,
                }).envelopeHash,
            describeBgvRnsParameters: (): BgvRnsParametersDescription =>
                executeCommand<BgvRnsParametersDescription>({
                    command: 'DescribeBgvRnsParameters',
                }),
            describeCollectiveBgvSetupParameters: (
                input,
            ): BgvCollectiveSetupParametersDescription =>
                executeCommand<BgvCollectiveSetupParametersDescription>({
                    command: 'DescribeCollectiveBgvSetupParameters',
                    ...(input?.participantCount === undefined
                        ? {}
                        : { participantCount: input.participantCount }),
                }),
        };
        registerPrivateKernelContexts(kernel, runtime);
        if (localStorageRootCommand !== undefined) {
            registerLocalStorageRootKernelContext(kernel, {
                allocate,
                command: localStorageRootCommand,
                deallocate,
                memory,
                runExclusive: runExclusiveKernelOperation,
            });
        }
        if (
            boardVerifierBegin !== undefined &&
            boardVerifierCachedCarrierLength !== undefined &&
            boardVerifierCancel !== undefined &&
            boardVerifierCopyCachedCarrier !== undefined &&
            boardVerifierDescribe !== undefined &&
            boardVerifierRelease !== undefined &&
            boardVerifierVerifyUnordered !== undefined
        ) {
            registerCanonicalBoardKernelContext(kernel, {
                allocate,
                begin: boardVerifierBegin,
                cachedCarrierLength: boardVerifierCachedCarrierLength,
                cancel: boardVerifierCancel,
                copyCachedCarrier: boardVerifierCopyCachedCarrier,
                deallocate,
                describe: boardVerifierDescribe,
                memory,
                release: boardVerifierRelease,
                runExclusive: runExclusiveKernelOperation,
                verifyUnordered: boardVerifierVerifyUnordered,
            });
        }
        if (
            finalityVerifierBegin !== undefined &&
            finalityVerifierCancel !== undefined &&
            finalityVerifierDescribe !== undefined &&
            finalityVerifierRelease !== undefined &&
            finalityVerifierVerify !== undefined
        ) {
            registerFinalityVerifierKernelContext(kernel, {
                allocate,
                begin: finalityVerifierBegin,
                cancel: finalityVerifierCancel,
                deallocate,
                describe: finalityVerifierDescribe,
                memory,
                release: finalityVerifierRelease,
                runExclusive: runExclusiveKernelOperation,
                verify: finalityVerifierVerify,
            });
        }
        if (
            stateVerifierBegin !== undefined &&
            stateVerifierCancel !== undefined &&
            stateVerifierCertifyIntent !== undefined &&
            stateVerifierCertifyUnorderedVotes !== undefined &&
            stateVerifierDescribe !== undefined &&
            stateVerifierRelease !== undefined &&
            stateVerifierFinishOutput !== undefined &&
            stateVerifierPrepareOutput !== undefined &&
            stateVerifierPrepareReservation !== undefined &&
            stateProducerCommand !== undefined &&
            stateVerifierVerifyReservation !== undefined
        ) {
            registerStateVerifierKernelContext(kernel, {
                allocate,
                begin: stateVerifierBegin,
                cancel: stateVerifierCancel,
                certifyIntent: stateVerifierCertifyIntent,
                certifyUnorderedVotes: stateVerifierCertifyUnorderedVotes,
                deallocate,
                describe: stateVerifierDescribe,
                memory,
                release: stateVerifierRelease,
                runExclusive: runExclusiveKernelOperation,
                finishOutput: stateVerifierFinishOutput,
                prepareOutput: stateVerifierPrepareOutput,
                prepareReservation: stateVerifierPrepareReservation,
                producerCommand: stateProducerCommand,
                verifyReservation: stateVerifierVerifyReservation,
            });
        }
        return kernel;
    });
