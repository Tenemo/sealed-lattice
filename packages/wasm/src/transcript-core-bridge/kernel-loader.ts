import type {
    FieldElement,
    ParticipantIdentity,
    ProtocolHash,
} from '@sealed-lattice/types';
import {
    foundationProfile,
    parseParticipantIdentity,
} from '@sealed-lattice/types';

import { registerCanonicalStreamKernelContext } from '../canonical-stream-runtime.js';
import { registerFoundationBoardKernelContext } from '../foundation-board-session.js';
import { registerStateVerifierKernelContext } from '../state-verifier-runtime.js';

import type {
    BgvCanonicalObjectAnalysis,
    BgvBatchPlaintextEncoding,
    BgvCollectiveSetupParametersDescription,
    BgvCollectiveSetupPublicDerivations,
    BgvCollectiveSetupVerification,
    BgvTrusteeEvaluationKeyProofGeneration,
    BgvTrusteeEvaluationKeyStatementDescription,
    BgvEvaluatorOperationValidation,
    BgvLocalTrusteeSetupStateVerification,
    BgvObjectValidation,
    BgvPassiveSetupPackage,
    BgvPrivateVssShareEnvelopeVerification,
    BgvPrivateVssShareProofGeneration,
    BgvOperationRejection,
    BgvRnsParametersDescription,
    BgvSameSecretBridgeProofGeneration,
    BgvVssCommittedMaterialCommitmentComputation,
    BgvVssShareLinkageProofGeneration,
    BgvSetupCommitmentOpeningComputation,
    BgvTargetDecryptionReleaseSetupContext,
    BgvTargetDecryptionShare,
    BgvTargetDecryptionShareProofMaterial,
    BgvTargetDecryptionShareProofMaterialVerification,
    BgvTargetDecryptionShareProofStatement,
    BgvTargetDecryptionShareProofStatementBinding,
    BgvTargetDecryptionResultReleaseBegin,
    BgvTargetDecryptionResultReleaseShareAbsorption,
    BgvTargetDecryptionResultReleaseCompletion,
    FoundationCanonicalTupleValidation,
    FoundationSchemaObjectValidation,
    TranscriptCoreKernel,
    TranscriptCoreKernelCommand,
    TranscriptCoreKernelExports,
    TranscriptCorePlaintextComparison,
} from './kernel-contracts.js';
import { bytesToHex } from './kernel-contracts.js';
import type { TranscriptCoreKernelLoaderOptions } from './kernel-runtime.js';
import {
    TranscriptCoreKernelCommandError,
    copyFromKernelMemory,
    copyIntoKernelMemory,
    requireKernelIntegrityExpectation,
    resolveKernelBytes,
    resolveMemory,
    resolveNumberExport,
    runKernelCommand,
    verifyKernelIntegrity,
} from './kernel-runtime.js';
import { registerLocalStorageRootKernelContext } from './local-storage-root-kernel-context.js';

const maximumFoundationSchemaObjectByteLength =
    foundationProfile.maximumCopiedBufferByteLength;

const typedArrayPrototype = Reflect.getPrototypeOf(Uint8Array.prototype);

const isUint8Array = (value: unknown): value is Uint8Array =>
    ArrayBuffer.isView(value) &&
    typedArrayPrototype !== null &&
    Reflect.get(typedArrayPrototype, Symbol.toStringTag, value) ===
        'Uint8Array';

export const createTranscriptCoreKernelLoader = (
    transcriptCoreKernelUrl: URL,
    options: TranscriptCoreKernelLoaderOptions = {},
): (() => Promise<TranscriptCoreKernel>) => {
    let kernelPromise: Promise<TranscriptCoreKernel> | undefined;

    return async (): Promise<TranscriptCoreKernel> => {
        kernelPromise ??= (async (): Promise<TranscriptCoreKernel> => {
            const expectedKernelSha256Hex =
                requireKernelIntegrityExpectation(options);
            const bytes = await resolveKernelBytes(transcriptCoreKernelUrl);
            if (expectedKernelSha256Hex !== undefined) {
                await verifyKernelIntegrity(bytes, expectedKernelSha256Hex);
            }
            const instantiatedSource = await WebAssembly.instantiate(bytes, {});
            const exports = instantiatedSource.instance
                .exports as TranscriptCoreKernelExports;
            const memory = resolveMemory(exports);
            const allocate = resolveNumberExport(
                exports,
                'sealed_lattice_allocate',
            ) as (length: number) => number;
            const deallocate = resolveNumberExport(
                exports,
                'sealed_lattice_deallocate',
            );
            const hasCanonicalStreamBoundary =
                typeof exports.sealed_lattice_canonical_stream_absorb_chunk ===
                'function';
            const canonicalStreamAbsorbChunk = hasCanonicalStreamBoundary
                ? (resolveNumberExport(
                      exports,
                      'sealed_lattice_canonical_stream_absorb_chunk',
                  ) as NonNullable<
                      TranscriptCoreKernelExports['sealed_lattice_canonical_stream_absorb_chunk']
                  >)
                : undefined;
            const canonicalStreamBeginVerifier = hasCanonicalStreamBoundary
                ? (resolveNumberExport(
                      exports,
                      'sealed_lattice_canonical_stream_begin_verifier',
                  ) as NonNullable<
                      TranscriptCoreKernelExports['sealed_lattice_canonical_stream_begin_verifier']
                  >)
                : undefined;
            const canonicalStreamBeginWriter = hasCanonicalStreamBoundary
                ? (resolveNumberExport(
                      exports,
                      'sealed_lattice_canonical_stream_begin_writer',
                  ) as NonNullable<
                      TranscriptCoreKernelExports['sealed_lattice_canonical_stream_begin_writer']
                  >)
                : undefined;
            const canonicalStreamCancel = hasCanonicalStreamBoundary
                ? (resolveNumberExport(
                      exports,
                      'sealed_lattice_canonical_stream_cancel',
                  ) as NonNullable<
                      TranscriptCoreKernelExports['sealed_lattice_canonical_stream_cancel']
                  >)
                : undefined;
            const canonicalStreamFinishVerifier = hasCanonicalStreamBoundary
                ? (resolveNumberExport(
                      exports,
                      'sealed_lattice_canonical_stream_finish_verifier',
                  ) as NonNullable<
                      TranscriptCoreKernelExports['sealed_lattice_canonical_stream_finish_verifier']
                  >)
                : undefined;
            const canonicalStreamFinishWriter = hasCanonicalStreamBoundary
                ? (resolveNumberExport(
                      exports,
                      'sealed_lattice_canonical_stream_finish_writer',
                  ) as NonNullable<
                      TranscriptCoreKernelExports['sealed_lattice_canonical_stream_finish_writer']
                  >)
                : undefined;
            const bgvCanonicalStreamAbsorbChunk =
                typeof exports.sealed_lattice_bgv_canonical_stream_absorb_chunk ===
                'function'
                    ? (resolveNumberExport(
                          exports,
                          'sealed_lattice_bgv_canonical_stream_absorb_chunk',
                      ) as NonNullable<
                          TranscriptCoreKernelExports['sealed_lattice_bgv_canonical_stream_absorb_chunk']
                      >)
                    : undefined;
            const bgvCanonicalStreamBegin =
                typeof exports.sealed_lattice_bgv_canonical_stream_begin ===
                'function'
                    ? (resolveNumberExport(
                          exports,
                          'sealed_lattice_bgv_canonical_stream_begin',
                      ) as NonNullable<
                          TranscriptCoreKernelExports['sealed_lattice_bgv_canonical_stream_begin']
                      >)
                    : undefined;
            const bgvCanonicalStreamCancel =
                typeof exports.sealed_lattice_bgv_canonical_stream_cancel ===
                'function'
                    ? (resolveNumberExport(
                          exports,
                          'sealed_lattice_bgv_canonical_stream_cancel',
                      ) as NonNullable<
                          TranscriptCoreKernelExports['sealed_lattice_bgv_canonical_stream_cancel']
                      >)
                    : undefined;
            const bgvCanonicalStreamFinish =
                typeof exports.sealed_lattice_bgv_canonical_stream_finish ===
                'function'
                    ? (resolveNumberExport(
                          exports,
                          'sealed_lattice_bgv_canonical_stream_finish',
                      ) as NonNullable<
                          TranscriptCoreKernelExports['sealed_lattice_bgv_canonical_stream_finish']
                      >)
                    : undefined;
            const bgvCanonicalMaterialReaderBegin =
                typeof exports.sealed_lattice_bgv_canonical_material_reader_begin ===
                'function'
                    ? (resolveNumberExport(
                          exports,
                          'sealed_lattice_bgv_canonical_material_reader_begin',
                      ) as NonNullable<
                          TranscriptCoreKernelExports['sealed_lattice_bgv_canonical_material_reader_begin']
                      >)
                    : undefined;
            const bgvCanonicalMaterialReaderCancel =
                typeof exports.sealed_lattice_bgv_canonical_material_reader_cancel ===
                'function'
                    ? (resolveNumberExport(
                          exports,
                          'sealed_lattice_bgv_canonical_material_reader_cancel',
                      ) as NonNullable<
                          TranscriptCoreKernelExports['sealed_lattice_bgv_canonical_material_reader_cancel']
                      >)
                    : undefined;
            const bgvCanonicalMaterialReaderFinish =
                typeof exports.sealed_lattice_bgv_canonical_material_reader_finish ===
                'function'
                    ? (resolveNumberExport(
                          exports,
                          'sealed_lattice_bgv_canonical_material_reader_finish',
                      ) as NonNullable<
                          TranscriptCoreKernelExports['sealed_lattice_bgv_canonical_material_reader_finish']
                      >)
                    : undefined;
            const bgvCanonicalMaterialReaderReadChunk =
                typeof exports.sealed_lattice_bgv_canonical_material_reader_read_chunk ===
                'function'
                    ? (resolveNumberExport(
                          exports,
                          'sealed_lattice_bgv_canonical_material_reader_read_chunk',
                      ) as NonNullable<
                          TranscriptCoreKernelExports['sealed_lattice_bgv_canonical_material_reader_read_chunk']
                      >)
                    : undefined;
            const foundationBoardBegin =
                typeof exports.sealed_lattice_foundation_board_begin ===
                'function'
                    ? (resolveNumberExport(
                          exports,
                          'sealed_lattice_foundation_board_begin',
                      ) as NonNullable<
                          TranscriptCoreKernelExports['sealed_lattice_foundation_board_begin']
                      >)
                    : undefined;
            const foundationBoardCancel =
                typeof exports.sealed_lattice_foundation_board_cancel ===
                'function'
                    ? (resolveNumberExport(
                          exports,
                          'sealed_lattice_foundation_board_cancel',
                      ) as NonNullable<
                          TranscriptCoreKernelExports['sealed_lattice_foundation_board_cancel']
                      >)
                    : undefined;
            const foundationBoardIngest =
                typeof exports.sealed_lattice_foundation_board_ingest ===
                'function'
                    ? (resolveNumberExport(
                          exports,
                          'sealed_lattice_foundation_board_ingest',
                      ) as NonNullable<
                          TranscriptCoreKernelExports['sealed_lattice_foundation_board_ingest']
                      >)
                    : undefined;
            const foundationBoardRequireCompleteCarrierGraph =
                typeof exports.sealed_lattice_foundation_board_require_complete_carrier_graph ===
                'function'
                    ? (resolveNumberExport(
                          exports,
                          'sealed_lattice_foundation_board_require_complete_carrier_graph',
                      ) as NonNullable<
                          TranscriptCoreKernelExports['sealed_lattice_foundation_board_require_complete_carrier_graph']
                      >)
                    : undefined;
            const localStorageRootCommand =
                typeof exports.sealed_lattice_local_storage_root_command ===
                'function'
                    ? (resolveNumberExport(
                          exports,
                          'sealed_lattice_local_storage_root_command',
                      ) as NonNullable<
                          TranscriptCoreKernelExports['sealed_lattice_local_storage_root_command']
                      >)
                    : undefined;
            const stateVerifierBegin =
                typeof exports.sealed_lattice_state_verifier_begin ===
                'function'
                    ? (resolveNumberExport(
                          exports,
                          'sealed_lattice_state_verifier_begin',
                      ) as NonNullable<
                          TranscriptCoreKernelExports['sealed_lattice_state_verifier_begin']
                      >)
                    : undefined;
            const stateVerifierCancel =
                typeof exports.sealed_lattice_state_verifier_cancel ===
                'function'
                    ? (resolveNumberExport(
                          exports,
                          'sealed_lattice_state_verifier_cancel',
                      ) as NonNullable<
                          TranscriptCoreKernelExports['sealed_lattice_state_verifier_cancel']
                      >)
                    : undefined;
            const stateVerifierRelease =
                typeof exports.sealed_lattice_state_verifier_release ===
                'function'
                    ? (resolveNumberExport(
                          exports,
                          'sealed_lattice_state_verifier_release',
                      ) as NonNullable<
                          TranscriptCoreKernelExports['sealed_lattice_state_verifier_release']
                      >)
                    : undefined;
            const stateVerifierFinishOutput =
                typeof exports.sealed_lattice_state_verifier_finish_output ===
                'function'
                    ? (resolveNumberExport(
                          exports,
                          'sealed_lattice_state_verifier_finish_output',
                      ) as NonNullable<
                          TranscriptCoreKernelExports['sealed_lattice_state_verifier_finish_output']
                      >)
                    : undefined;
            const stateVerifierVerifyRecovery =
                typeof exports.sealed_lattice_state_verifier_verify_recovery ===
                'function'
                    ? (resolveNumberExport(
                          exports,
                          'sealed_lattice_state_verifier_verify_recovery',
                      ) as NonNullable<
                          TranscriptCoreKernelExports['sealed_lattice_state_verifier_verify_recovery']
                      >)
                    : undefined;
            const stateVerifierVerifyReservation =
                typeof exports.sealed_lattice_state_verifier_verify_reservation ===
                'function'
                    ? (resolveNumberExport(
                          exports,
                          'sealed_lattice_state_verifier_verify_reservation',
                      ) as NonNullable<
                          TranscriptCoreKernelExports['sealed_lattice_state_verifier_verify_reservation']
                      >)
                    : undefined;
            const transcriptCoreCommandWithLength = resolveNumberExport(
                exports,
                'sealed_lattice_transcript_core_command_with_length',
            ) as (
                pointer: number,
                length: number,
                outputLengthPointer: number,
            ) => number;
            const roundtrip = resolveNumberExport(
                exports,
                'sealed_lattice_roundtrip',
            ) as (pointer: number, length: number) => number;
            const exportedFunctionNames = WebAssembly.Module.exports(
                instantiatedSource.module,
            )
                .map((entry) => entry.name)
                .sort();
            // This guards a single synchronous allocate/run/free cycle only; multi-call transport streams are kept separate by their kernel-side id, not by this flag.
            let kernelOperationInProgress = false;
            // One WASM instance has a single shared linear memory and allocator, so
            // overlapping commands would corrupt each other's buffers; the kernel is
            // single-threaded by contract, so reject any re-entrant operation.
            const runExclusiveKernelOperation = <Result>(
                operationName: string,
                operation: () => Result,
            ): Result => {
                if (kernelOperationInProgress) {
                    throw new Error(
                        `The transcript-core kernel cannot run overlapping ${operationName} operations on one instance.`,
                    );
                }
                kernelOperationInProgress = true;
                try {
                    return operation();
                } finally {
                    kernelOperationInProgress = false;
                }
            };
            const executeCommand = <T>(
                request: TranscriptCoreKernelCommand,
            ): T =>
                runExclusiveKernelOperation('command', () =>
                    runKernelCommand<T>(
                        memory,
                        allocate,
                        deallocate,
                        transcriptCoreCommandWithLength,
                        request,
                    ),
                );
            // Accepted setup is real protocol input, not a fixture, so a fixture-shaped rejection is surfaced as a rejected protocol object rather than leaking the kernel fixture error code.
            const executeAcceptedSetupCommand = <
                Result extends BgvCollectiveSetupVerification,
            >(
                request: TranscriptCoreKernelCommand,
            ): Result => {
                try {
                    return executeCommand<Result>(request);
                } catch (error) {
                    if (
                        error instanceof TranscriptCoreKernelCommandError &&
                        error.code === 'InvalidFixture'
                    ) {
                        const message = error.message.replace(
                            /^InvalidFixture: /u,
                            '',
                        );
                        throw new TranscriptCoreKernelCommandError({
                            code: 'InvalidProtocolObject',
                            message,
                        });
                    }

                    throw error;
                }
            };

            const kernel: TranscriptCoreKernel = {
                exportedFunctionNames,
                computeChunkRoot: (input): string =>
                    executeCommand<{ readonly chunkRoot: string }>({
                        command: 'ComputeChunkRoot',
                        inputHex: input.inputHex,
                        chunkSize: input.chunkSize,
                    }).chunkRoot,
                computeFoundationHash512: (input): ProtocolHash =>
                    executeCommand<{ readonly hash512: ProtocolHash }>({
                        command: 'ComputeFoundationHash512',
                        domain: input.domain,
                        canonicalItemsTupleHex: input.canonicalItemsTupleHex,
                    }).hash512,
                deriveFoundationParticipantIdentity: (
                    input,
                ): ParticipantIdentity => {
                    const response = executeCommand<{
                        readonly participantIdentity: unknown;
                    }>({
                        command: 'DeriveFoundationParticipantIdentity',
                        signingVerificationKeyHex:
                            input.signingVerificationKeyHex,
                    });

                    return parseParticipantIdentity(
                        response.participantIdentity,
                    );
                },
                deriveCanonicalObjectHash: (input): ProtocolHash =>
                    executeCommand<{
                        readonly canonicalObjectHash: ProtocolHash;
                    }>({
                        command: 'DeriveCanonicalObjectHash',
                        value: input.value,
                    }).canonicalObjectHash,
                evaluatePlaintextComparison: (
                    input,
                ): TranscriptCorePlaintextComparison =>
                    executeCommand<TranscriptCorePlaintextComparison>({
                        command: 'EvaluatePlaintextComparison',
                        leftTotalScore: input.leftTotalScore,
                        rightTotalScore: input.rightTotalScore,
                        rosterSize: input.rosterSize,
                    }),
                hashRaw: (inputHex): string =>
                    executeCommand<{ readonly hash512: string }>({
                        command: 'HashRaw',
                        inputHex,
                    }).hash512,
                interpolateShamirConstantTerm: (input): FieldElement =>
                    executeCommand<{ readonly fieldElement: FieldElement }>({
                        command: 'InterpolateShamirConstantTerm',
                        sharePoints: input.sharePoints,
                    }).fieldElement,
                listCanonicalErrorCodes: (): readonly string[] =>
                    executeCommand<readonly string[]>({
                        command: 'ListCanonicalErrorCodes',
                    }),
                roundTripBytes: (input: Uint8Array): Uint8Array =>
                    runExclusiveKernelOperation('round-trip', () => {
                        const normalizedInput = Uint8Array.from(input);
                        let inputPointer = 0;
                        let outputPointer = 0;

                        try {
                            inputPointer = copyIntoKernelMemory(
                                memory,
                                allocate,
                                normalizedInput,
                            );
                            outputPointer = roundtrip(
                                inputPointer,
                                normalizedInput.length,
                            );

                            return copyFromKernelMemory(
                                memory,
                                outputPointer,
                                normalizedInput.length,
                                'round-trip',
                            );
                        } finally {
                            if (outputPointer !== 0) {
                                deallocate(
                                    outputPointer,
                                    normalizedInput.length,
                                );
                            }
                            if (
                                inputPointer !== 0 &&
                                inputPointer !== outputPointer
                            ) {
                                deallocate(
                                    inputPointer,
                                    normalizedInput.length,
                                );
                            }
                        }
                    }),
                validateFoundationCanonicalTuple: (
                    input,
                ): FoundationCanonicalTupleValidation =>
                    executeCommand<FoundationCanonicalTupleValidation>({
                        command: 'ValidateFoundationCanonicalTuple',
                        canonicalTupleHex: input.canonicalTupleHex,
                    }),
                validateFoundationSchemaObject: (
                    input,
                ): FoundationSchemaObjectValidation => {
                    if (!isUint8Array(input.canonicalBytes)) {
                        throw new TranscriptCoreKernelCommandError({
                            code: 'InvalidProtocolObject',
                            message:
                                'foundation schema object must be a Uint8Array',
                        });
                    }
                    if (
                        input.canonicalBytes.byteLength >
                        maximumFoundationSchemaObjectByteLength
                    ) {
                        throw new TranscriptCoreKernelCommandError({
                            code: 'MalformedLength',
                            message:
                                'foundation schema object exceeds the accepted byte length',
                        });
                    }
                    const canonicalBytes = new Uint8Array(
                        input.canonicalBytes.byteLength,
                    );
                    canonicalBytes.set(input.canonicalBytes);
                    return executeCommand<FoundationSchemaObjectValidation>({
                        command: 'ValidateFoundationSchemaObject',
                        canonicalObjectHex: bytesToHex(canonicalBytes),
                    });
                },
                generateBgvTargetDecryptionShareFromLocalShare: (
                    input,
                ): BgvTargetDecryptionShare =>
                    executeCommand<BgvTargetDecryptionShare>({
                        command:
                            'GenerateBgvTargetDecryptionShareFromLocalShare',
                        setupPackage: input.setupPackage,
                        targetAcceptedRecord: input.targetAcceptedRecord,
                        targetCiphertexts: input.targetCiphertexts,
                        targetCiphertextBinding: input.targetCiphertextBinding,
                        targetShareProfile: input.targetShareProfile,
                        trusteeIdentity: input.trusteeIdentity,
                        localTargetShareWitness: input.localTargetShareWitness,
                    }),
                deriveBgvTargetDecryptionShareProofStatement: (
                    input,
                ): BgvTargetDecryptionShareProofStatement =>
                    executeCommand<BgvTargetDecryptionShareProofStatement>({
                        command: 'DeriveBgvTargetDecryptionShareProofStatement',
                        setupPackage: input.setupPackage,
                        targetAcceptedRecord: input.targetAcceptedRecord,
                        targetCiphertexts: input.targetCiphertexts,
                        targetCiphertextBinding: input.targetCiphertextBinding,
                        targetShareProfile: input.targetShareProfile,
                        trusteeIdentity: input.trusteeIdentity,
                        localTargetShareWitness: input.localTargetShareWitness,
                        targetDecryptionShare: input.targetDecryptionShare,
                    }),
                generateBgvTargetDecryptionShareProofMaterialFromLocalWitness: (
                    input,
                ): BgvTargetDecryptionShareProofMaterial =>
                    executeCommand<BgvTargetDecryptionShareProofMaterial>({
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
                verifyBgvTargetDecryptionShareProofMaterial: (
                    input,
                ): BgvTargetDecryptionShareProofMaterialVerification =>
                    executeCommand<BgvTargetDecryptionShareProofMaterialVerification>(
                        {
                            command:
                                'VerifyBgvTargetDecryptionShareProofMaterial',
                            setupPackage: input.setupPackage,
                            targetAcceptedRecord: input.targetAcceptedRecord,
                            targetCiphertexts: input.targetCiphertexts,
                            targetCiphertextBinding:
                                input.targetCiphertextBinding,
                            targetShareProfile: input.targetShareProfile,
                            targetDecryptionShare: input.targetDecryptionShare,
                            proofStatement: input.proofStatement,
                            proofMaterial: input.proofMaterial,
                        },
                    ),
                verifyBgvTargetDecryptionShareProofStatementBinding: (
                    input,
                ): BgvTargetDecryptionShareProofStatementBinding =>
                    executeCommand<BgvTargetDecryptionShareProofStatementBinding>(
                        {
                            command:
                                'VerifyBgvTargetDecryptionShareProofStatementBinding',
                            setupPackage: input.setupPackage,
                            targetAcceptedRecord: input.targetAcceptedRecord,
                            targetCiphertexts: input.targetCiphertexts,
                            targetCiphertextBinding:
                                input.targetCiphertextBinding,
                            targetShareProfile: input.targetShareProfile,
                            targetDecryptionShare: input.targetDecryptionShare,
                            proofStatement: input.proofStatement,
                        },
                    ),
                describeBgvRnsParameters: (): BgvRnsParametersDescription =>
                    executeCommand<BgvRnsParametersDescription>({
                        command: 'DescribeBgvRnsParameters',
                    }),
                describeBgvOperationRegistry: (): unknown =>
                    executeCommand<unknown>({
                        command: 'DescribeBgvOperationRegistry',
                    }),
                validateBgvEvaluatorOperation: (
                    input,
                ): BgvEvaluatorOperationValidation =>
                    executeCommand<BgvEvaluatorOperationValidation>({
                        command: 'ValidateBgvEvaluatorOperation',
                        operation: input.operation,
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
                deriveCollectiveBgvSetupPublicDerivations: (
                    input,
                ): BgvCollectiveSetupPublicDerivations =>
                    executeCommand<BgvCollectiveSetupPublicDerivations>({
                        command: 'DeriveCollectiveBgvSetupPublicDerivations',
                        publicMatrixSeedHash: input.publicMatrixSeedHash,
                        ...(input.decryptionThreshold === undefined
                            ? {}
                            : {
                                  decryptionThreshold:
                                      input.decryptionThreshold,
                              }),
                    }),
                generateBgvPassiveSetup: (input): BgvPassiveSetupPackage =>
                    executeCommand<BgvPassiveSetupPackage>({
                        command: 'GenerateBgvPassiveSetup',
                        ceremonyId: input.ceremonyId,
                        manifestHash: input.manifestHash,
                        rosterHash: input.rosterHash,
                        thresholdParametersHash: input.thresholdParametersHash,
                        participants: input.participants,
                        setupSeed: input.setupSeed,
                    }),
                verifyBgvPassiveSetup: (input): void =>
                    executeCommand<void>({
                        command: 'VerifyBgvPassiveSetup',
                        setupPackage: input.setupPackage,
                        expectedSetupPackageHash:
                            input.expectedSetupPackageHash,
                        expectedManifestHash: input.expectedManifestHash,
                        expectedRosterHash: input.expectedRosterHash,
                        expectedCollectivePublicKeyRoot:
                            input.expectedCollectivePublicKeyRoot,
                        expectedRotSetHash: input.expectedRotSetHash,
                        expectedEvaluationKeyRoot:
                            input.expectedEvaluationKeyRoot,
                    }),
                verifyCollectiveBgvSetup: (
                    input,
                ): BgvCollectiveSetupVerification =>
                    executeAcceptedSetupCommand<BgvCollectiveSetupVerification>(
                        {
                            command: 'VerifyCollectiveBgvSetup',
                            setupPackage: input.setupPackage,
                            expectedSetupPackageHash:
                                input.expectedSetupPackageHash,
                            expectedManifestHash: input.expectedManifestHash,
                            expectedRosterHash: input.expectedRosterHash,
                            transportedPublicKeyShareMaterial:
                                input.transportedPublicKeyShareMaterial,
                            transportedPublicKeyShareProofMaterial:
                                input.transportedPublicKeyShareProofMaterial,
                            transportedEvaluationKeyShareProofMaterial:
                                input.transportedEvaluationKeyShareProofMaterial,
                            transportedVssShareLinkageProofMaterial:
                                input.transportedVssShareLinkageProofMaterial,
                            transportedSameSecretBridgeProofMaterial:
                                input.transportedSameSecretBridgeProofMaterial,
                            transportedEvaluationKeyShareComponentMaterial:
                                input.transportedEvaluationKeyShareComponentMaterial,
                            transportedEvaluationKeyAggregateBindingOpenings:
                                input.transportedEvaluationKeyAggregateBindingOpenings,
                            transportedPublicEvaluationKeyMaterial:
                                input.transportedPublicEvaluationKeyMaterial,
                        },
                    ),
                verifyPrivateVssShareEnvelope: (
                    input,
                ): BgvPrivateVssShareEnvelopeVerification =>
                    executeCommand<BgvPrivateVssShareEnvelopeVerification>({
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
                        expectedPrivateEnvelopeHash:
                            input.expectedPrivateEnvelopeHash,
                        expectedLocalVerificationRoot:
                            input.expectedLocalVerificationRoot,
                    }),
                generatePrivateVssShareProof: (
                    input,
                ): BgvPrivateVssShareProofGeneration =>
                    executeCommand<BgvPrivateVssShareProofGeneration>({
                        command: 'GeneratePrivateVssShareProof',
                        setupContext: input.setupContext,
                        publicMatrixSeedHash: input.publicMatrixSeedHash,
                        privateEnvelopeAadHash: input.privateEnvelopeAadHash,
                        sourceTrusteeCoefficientCommitmentRecord:
                            input.sourceTrusteeCoefficientCommitmentRecord,
                        sourceTrusteeCoefficientCommitmentMaterialRecords:
                            input.sourceTrusteeCoefficientCommitmentMaterialRecords,
                        recipientIdentity: input.recipientIdentity,
                        recipientRosterPosition: input.recipientRosterPosition,
                        rnsLimbIndex: input.rnsLimbIndex,
                        rnsPrime: input.rnsPrime,
                        ringDegree: input.ringDegree,
                        shareValues: input.shareValues,
                        coefficientCommitmentRoots:
                            input.coefficientCommitmentRoots,
                        coefficientMessagesByShamirIndex:
                            input.coefficientMessagesByShamirIndex,
                        openingRandomnessByShamirIndex:
                            input.openingRandomnessByShamirIndex,
                        proofRandomnessSeedHex: input.proofRandomnessSeedHex,
                        proofRandomnessNonceHex: input.proofRandomnessNonceHex,
                    }),
                generateTrusteeEvaluationKeyProof: (
                    input,
                ): BgvTrusteeEvaluationKeyProofGeneration =>
                    executeCommand<BgvTrusteeEvaluationKeyProofGeneration>({
                        command: 'GenerateTrusteeEvaluationKeyProof',
                        context: input.context,
                        ringDegree: input.ringDegree,
                        keys: input.keys,
                        sameSecretLinkage: input.sameSecretLinkage,
                        sameSecretBridge: input.sameSecretBridge,
                        secretCoefficients: input.secretCoefficients,
                        errorCoefficientsByKey: input.errorCoefficientsByKey,
                        negativeIndicatorCoefficients:
                            input.negativeIndicatorCoefficients,
                        openingRandomnessByLimb: input.openingRandomnessByLimb,
                        vssCommittedMaterialSeedsByBoundMessage:
                            input.vssCommittedMaterialSeedsByBoundMessage,
                        vssCommittedMaterialContextHashesByBoundMessage:
                            input.vssCommittedMaterialContextHashesByBoundMessage,
                        proofRandomnessSeedHex: input.proofRandomnessSeedHex,
                        proofRandomnessNonceHex: input.proofRandomnessNonceHex,
                    }),
                describeTrusteeEvaluationKeyStatement: (
                    input,
                ): BgvTrusteeEvaluationKeyStatementDescription =>
                    executeCommand<BgvTrusteeEvaluationKeyStatementDescription>(
                        {
                            command: 'DescribeTrusteeEvaluationKeyStatement',
                            context: input.context,
                            ringDegree: input.ringDegree,
                            keys: input.keys,
                            sameSecretLinkage: input.sameSecretLinkage,
                            sameSecretBridge: input.sameSecretBridge,
                        },
                    ),
                computeSetupCommitmentFromOpening: (
                    input,
                ): BgvSetupCommitmentOpeningComputation =>
                    executeCommand<BgvSetupCommitmentOpeningComputation>({
                        command: 'ComputeSetupCommitmentFromOpening',
                        publicMatrixSeedHash: input.publicMatrixSeedHash,
                        sourceRnsLimbIndex: input.sourceRnsLimbIndex,
                        sourceMessageModulus: input.sourceMessageModulus,
                        shamirCoefficientIndex: input.shamirCoefficientIndex,
                        messageCoefficients: input.messageCoefficients,
                        randomnessByColumn: input.randomnessByColumn,
                        ringDegree: input.ringDegree,
                    }),
                computeVssCommittedMaterialCommitment: (
                    input,
                ): BgvVssCommittedMaterialCommitmentComputation =>
                    executeCommand<BgvVssCommittedMaterialCommitmentComputation>(
                        {
                            command: 'ComputeVssCommittedMaterialCommitment',
                            commitmentRole: input.commitmentRole,
                            commitmentContext: input.commitmentContext,
                            rnsLimbIndex: input.rnsLimbIndex,
                            rnsPrime: input.rnsPrime,
                            ringDegree: input.ringDegree,
                            ...(input.messageCoefficientBound === undefined
                                ? {}
                                : {
                                      messageCoefficientBound:
                                          input.messageCoefficientBound,
                                  }),
                            messageCoefficients: input.messageCoefficients,
                            materialSeedHex: input.materialSeedHex,
                        },
                    ),
                generateVssShareLinkageProof: (
                    input,
                ): BgvVssShareLinkageProofGeneration =>
                    executeCommand<BgvVssShareLinkageProofGeneration>({
                        command: 'GenerateVssShareLinkageProof',
                        context: input.context,
                        ringDegree: input.ringDegree,
                        vssShareLinkage: input.vssShareLinkage,
                        coefficientMessagesByShamirIndex:
                            input.coefficientMessagesByShamirIndex,
                        recipientShareMessages: input.recipientShareMessages,
                        coefficientOpeningRandomnessByShamirIndex:
                            input.coefficientOpeningRandomnessByShamirIndex,
                        recipientShareOpeningRandomness:
                            input.recipientShareOpeningRandomness,
                        carryWitnesses: input.carryWitnesses,
                        recipientShareMessagesByItem:
                            input.recipientShareMessagesByItem,
                        recipientShareOpeningRandomnessByItem:
                            input.recipientShareOpeningRandomnessByItem,
                        carryWitnessesByItem: input.carryWitnessesByItem,
                        vssCommittedMaterialSeedsByBoundMessage:
                            input.vssCommittedMaterialSeedsByBoundMessage,
                        vssCommittedMaterialContextHashesByBoundMessage:
                            input.vssCommittedMaterialContextHashesByBoundMessage,
                        proofRandomnessSeedHex: input.proofRandomnessSeedHex,
                        proofRandomnessNonceHex: input.proofRandomnessNonceHex,
                    }),
                generateSameSecretBridgeProof: (
                    input,
                ): BgvSameSecretBridgeProofGeneration =>
                    executeCommand<BgvSameSecretBridgeProofGeneration>({
                        command: 'GenerateSameSecretBridgeProof',
                        context: input.context,
                        ringDegree: input.ringDegree,
                        sameSecretLinkage: input.sameSecretLinkage,
                        sameSecretBridge: input.sameSecretBridge,
                        secretCoefficients: input.secretCoefficients,
                        negativeIndicatorCoefficients:
                            input.negativeIndicatorCoefficients,
                        openingRandomnessByLimb: input.openingRandomnessByLimb,
                        vssCommittedMaterialSeedsByBoundMessage:
                            input.vssCommittedMaterialSeedsByBoundMessage,
                        vssCommittedMaterialContextHashesByBoundMessage:
                            input.vssCommittedMaterialContextHashesByBoundMessage,
                        proofRandomnessSeedHex: input.proofRandomnessSeedHex,
                        proofRandomnessNonceHex: input.proofRandomnessNonceHex,
                    }),
                deriveBgvTargetDecryptionResultReleaseSetupContext: (
                    input,
                ): BgvTargetDecryptionReleaseSetupContext =>
                    executeCommand<BgvTargetDecryptionReleaseSetupContext>({
                        command:
                            'DeriveBgvTargetDecryptionResultReleaseSetupContext',
                        setupPackage: input.setupPackage,
                    }),
                beginBgvTargetDecryptionResultRelease: (
                    input,
                ): BgvTargetDecryptionResultReleaseBegin =>
                    executeCommand<BgvTargetDecryptionResultReleaseBegin>({
                        command: 'BeginBgvTargetDecryptionResultRelease',
                        releaseVerificationId: input.releaseVerificationId,
                        releaseSetupContext: input.releaseSetupContext,
                        targetAcceptedRecord: input.targetAcceptedRecord,
                        targetCiphertexts: input.targetCiphertexts,
                        targetCiphertextBinding: input.targetCiphertextBinding,
                        targetShareProfile: input.targetShareProfile,
                    }),
                absorbBgvTargetDecryptionResultReleaseShare: (
                    input,
                ): BgvTargetDecryptionResultReleaseShareAbsorption =>
                    executeCommand<BgvTargetDecryptionResultReleaseShareAbsorption>(
                        {
                            command:
                                'AbsorbBgvTargetDecryptionResultReleaseShare',
                            releaseVerificationId: input.releaseVerificationId,
                            targetShareProof: input.targetShareProof,
                        },
                    ),
                finishBgvTargetDecryptionResultRelease: (
                    input,
                ): BgvTargetDecryptionResultReleaseCompletion =>
                    executeCommand<BgvTargetDecryptionResultReleaseCompletion>({
                        command: 'FinishBgvTargetDecryptionResultRelease',
                        releaseVerificationId: input.releaseVerificationId,
                    }),
                verifyLocalTrusteeSetupState: (
                    input,
                ): BgvLocalTrusteeSetupStateVerification =>
                    executeCommand<BgvLocalTrusteeSetupStateVerification>({
                        command: 'VerifyLocalTrusteeSetupState',
                        setupContext: input.setupContext,
                        localStateCommitment: input.localStateCommitment,
                    }),
                encodeBgvBatchPlaintext: (
                    input,
                ): BgvBatchPlaintextEncoding | BgvOperationRejection =>
                    executeCommand<
                        BgvBatchPlaintextEncoding | BgvOperationRejection
                    >({
                        command: 'EncodeBgvBatchPlaintext',
                        slots: input.slots,
                        level: input.level,
                        includeCanonicalBytesHex:
                            input.includeCanonicalBytesHex,
                    }),
                validateBgvPlaintextObject: (
                    input,
                ): BgvObjectValidation | BgvOperationRejection =>
                    executeCommand<BgvObjectValidation | BgvOperationRejection>(
                        {
                            command: 'ValidateBgvPlaintextObject',
                            canonicalBytesHex: input.canonicalBytesHex,
                            expectedPlaintextRoot: input.expectedPlaintextRoot,
                        },
                    ),
                validateBgvCiphertextObject: (
                    input,
                ): BgvObjectValidation | BgvOperationRejection =>
                    executeCommand<BgvObjectValidation | BgvOperationRejection>(
                        {
                            command: 'ValidateBgvCiphertextObject',
                            canonicalBytesHex: input.canonicalBytesHex,
                            expectedCiphertextRoot:
                                input.expectedCiphertextRoot,
                        },
                    ),
                analyzeBgvCanonicalObject: (
                    input,
                ): BgvCanonicalObjectAnalysis | BgvOperationRejection =>
                    executeCommand<
                        BgvCanonicalObjectAnalysis | BgvOperationRejection
                    >({
                        command: 'AnalyzeBgvCanonicalObject',
                        canonicalBytesHex: input.canonicalBytesHex,
                    }),
            };
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
                    allocate,
                    bgvAbsorbChunk: bgvCanonicalStreamAbsorbChunk,
                    bgvBegin: bgvCanonicalStreamBegin,
                    bgvCancel: bgvCanonicalStreamCancel,
                    bgvFinish: bgvCanonicalStreamFinish,
                    bgvMaterialReaderBegin: bgvCanonicalMaterialReaderBegin,
                    bgvMaterialReaderCancel: bgvCanonicalMaterialReaderCancel,
                    bgvMaterialReaderFinish: bgvCanonicalMaterialReaderFinish,
                    bgvMaterialReaderReadChunk:
                        bgvCanonicalMaterialReaderReadChunk,
                    beginVerifier: canonicalStreamBeginVerifier,
                    beginWriter: canonicalStreamBeginWriter,
                    cancel: canonicalStreamCancel,
                    deallocate,
                    finishVerifier: canonicalStreamFinishVerifier,
                    finishWriter: canonicalStreamFinishWriter,
                    memory,
                    runExclusive: runExclusiveKernelOperation,
                });
            }
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
                foundationBoardBegin !== undefined &&
                foundationBoardCancel !== undefined &&
                foundationBoardIngest !== undefined &&
                foundationBoardRequireCompleteCarrierGraph !== undefined
            ) {
                registerFoundationBoardKernelContext(kernel, {
                    allocate,
                    begin: foundationBoardBegin,
                    cancel: foundationBoardCancel,
                    deallocate,
                    ingest: foundationBoardIngest,
                    memory,
                    requireCompleteCarrierGraph:
                        foundationBoardRequireCompleteCarrierGraph,
                    runExclusive: runExclusiveKernelOperation,
                });
            }
            if (
                stateVerifierBegin !== undefined &&
                stateVerifierCancel !== undefined &&
                stateVerifierRelease !== undefined &&
                stateVerifierFinishOutput !== undefined &&
                stateVerifierVerifyRecovery !== undefined &&
                stateVerifierVerifyReservation !== undefined
            ) {
                registerStateVerifierKernelContext(kernel, {
                    allocate,
                    begin: stateVerifierBegin,
                    cancel: stateVerifierCancel,
                    deallocate,
                    memory,
                    release: stateVerifierRelease,
                    runExclusive: runExclusiveKernelOperation,
                    finishOutput: stateVerifierFinishOutput,
                    verifyRecovery: stateVerifierVerifyRecovery,
                    verifyReservation: stateVerifierVerifyReservation,
                });
            }
            return kernel;
        })().catch((error: unknown) => {
            // Clear the cached promise on failure so a later call can retry
            // instantiation instead of permanently re-throwing the cached rejection.
            kernelPromise = undefined;
            throw error;
        });

        return kernelPromise;
    };
};
