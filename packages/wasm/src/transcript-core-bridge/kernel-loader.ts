import type { ProtocolHash } from '@sealed-lattice/types';

import { registerCanonicalBoardKernelContext } from '../canonical-board-runtime.js';
import { registerStateVerifierKernelContext } from '../state-verifier-runtime.js';

import type {
    BgvCollectiveSetupParametersDescription,
    BgvTrusteeEvaluationKeyProofGeneration,
    BgvRnsParametersDescription,
    BgvVssCommittedMaterialCommitmentComputation,
    BgvSetupCommitmentOpeningComputation,
    DecodedMailboxAssociatedData,
    DecodedMailboxKeyScheduleInput,
    DecodedProofApplicationBinding,
    DecodedPrivateRandomCursor,
    DecodedSignedMailboxEnvelope,
    DecodedStreamDescriptor,
    EncodedMailboxAssociatedData,
    EncodedMailboxKeyScheduleInput,
    EncodedPrivateRandomCursor,
    EncodedSignedMailboxEnvelope,
    EncodedStreamDescriptor,
    CanonicalFoundationValueValidation,
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
import { registerKernelContexts } from './register-kernel-contexts.js';

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
        const stateVerifierPrepareRecovery = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_state_verifier_prepare_recovery',
        );
        const stateVerifierPrepareReservation = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_state_verifier_prepare_reservation',
        );
        const stateVerifierVerifyRecovery = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_state_verifier_verify_recovery',
        );
        const stateVerifierVerifyReservation = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_state_verifier_verify_reservation',
        );
        const kernel: TranscriptCoreKernel = {
            ...createPublishedSdkKernelBindings(runtime, () => kernel),
            deriveCanonicalObjectHash: (input): ProtocolHash =>
                executeCommand<{
                    readonly canonicalObjectHash: ProtocolHash;
                }>({
                    command: 'DeriveCanonicalObjectHash',
                    value: input.value,
                }).canonicalObjectHash,
            validateCanonicalFoundationValue: (input) =>
                executeCommand<CanonicalFoundationValueValidation>({
                    command: 'ValidateCanonicalFoundationValue',
                    ...input,
                }),
            decodeProofApplicationBinding: (input) =>
                executeCommand<DecodedProofApplicationBinding>({
                    command: 'DecodeProofApplicationBinding',
                    canonicalBytesHex: input.canonicalBytesHex,
                }),
            deriveCeremonyContextHash: (value): ProtocolHash =>
                executeCommand<{
                    readonly ceremonyContextHash: ProtocolHash;
                }>({
                    command: 'DeriveCeremonyContextHash',
                    value,
                }).ceremonyContextHash,
            deriveActionContextHash: (value): ProtocolHash =>
                executeCommand<{
                    readonly actionContextHash: ProtocolHash;
                }>({
                    command: 'DeriveActionContextHash',
                    value,
                }).actionContextHash,
            encodeMailboxKeyScheduleInput: (value) =>
                executeCommand<EncodedMailboxKeyScheduleInput>({
                    command: 'EncodeMailboxKeyScheduleInput',
                    value,
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
            deriveMailboxKemCiphertextHash: (input): ProtocolHash =>
                executeCommand<{
                    readonly kemCiphertextHash: ProtocolHash;
                }>({
                    command: 'DeriveMailboxKemCiphertextHash',
                    kemCiphertextHex: input.kemCiphertextHex,
                }).kemCiphertextHash,
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
            generateTrusteeEvaluationKeyProof: (
                input,
            ): BgvTrusteeEvaluationKeyProofGeneration => {
                if (input.statementFamily === 'public-key-share') {
                    return executeCommand<BgvTrusteeEvaluationKeyProofGeneration>(
                        {
                            command: 'GenerateTrusteeEvaluationKeyProof',
                            context: input.context,
                            ringDegree: input.ringDegree,
                            keys: input.keys,
                            sameSecretBridge: input.sameSecretBridge,
                            secretCoefficients: input.secretCoefficients,
                            errorCoefficientsByKey:
                                input.errorCoefficientsByKey,
                            vssCommittedMaterialSeedsByBoundMessage:
                                input.vssCommittedMaterialSeedsByBoundMessage,
                            proofRandomnessSeedHex:
                                input.proofRandomnessSeedHex,
                        },
                    );
                }
                return executeCommand<BgvTrusteeEvaluationKeyProofGeneration>({
                    command: 'GenerateTrusteeEvaluationKeyProof',
                    context: input.context,
                    ringDegree: input.ringDegree,
                    keys: input.keys,
                    sameSecretLinkage: input.sameSecretLinkage,
                    secretCoefficients: input.secretCoefficients,
                    errorCoefficientsByKey: input.errorCoefficientsByKey,
                    openingRandomnessByLimb: input.openingRandomnessByLimb,
                    proofRandomnessSeedHex: input.proofRandomnessSeedHex,
                });
            },
            computeSetupCommitmentFromOpening: (
                input,
            ): BgvSetupCommitmentOpeningComputation =>
                executeCommand<BgvSetupCommitmentOpeningComputation>({
                    command: 'ComputeSetupCommitmentFromOpening',
                    publicMatrixSeedHash: input.publicMatrixSeedHash,
                    sourceRnsLimbIndex: input.sourceRnsLimbIndex,
                    shamirCoefficientIndex: input.shamirCoefficientIndex,
                    messageCoefficients: input.messageCoefficients,
                    randomnessByColumn: input.randomnessByColumn,
                    ringDegree: input.ringDegree,
                }),
            computeVssCommittedMaterialCommitment: (
                input,
            ): BgvVssCommittedMaterialCommitmentComputation =>
                executeCommand<BgvVssCommittedMaterialCommitmentComputation>({
                    command: 'ComputeVssCommittedMaterialCommitment',
                    commitmentRole: input.commitmentRole,
                    commitmentContext: input.commitmentContext,
                    rnsLimbIndex: input.rnsLimbIndex,
                    ringDegree: input.ringDegree,
                    messageCoefficients: input.messageCoefficients,
                    materialSeedHex: input.materialSeedHex,
                }),
        };
        registerKernelContexts(kernel, runtime);
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
            stateVerifierBegin !== undefined &&
            stateVerifierCancel !== undefined &&
            stateVerifierCertifyIntent !== undefined &&
            stateVerifierCertifyUnorderedVotes !== undefined &&
            stateVerifierDescribe !== undefined &&
            stateVerifierRelease !== undefined &&
            stateVerifierFinishOutput !== undefined &&
            stateVerifierPrepareOutput !== undefined &&
            stateVerifierPrepareRecovery !== undefined &&
            stateVerifierPrepareReservation !== undefined &&
            stateVerifierVerifyRecovery !== undefined &&
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
                prepareRecovery: stateVerifierPrepareRecovery,
                prepareReservation: stateVerifierPrepareReservation,
                verifyRecovery: stateVerifierVerifyRecovery,
                verifyReservation: stateVerifierVerifyReservation,
            });
        }
        return kernel;
    });
