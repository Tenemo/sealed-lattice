import { shake256 } from '@noble/hashes/sha3.js';
import { BrowserActionStorageCustodyError } from '@sealed-lattice/types';
import {
    openClosedWorkerCommonProofScratchStorage,
    type AuthenticatedCommonProofInputStore,
    type CommonProofCanonicalOutputStore,
    type CommonProofExternalMemoryReadResult,
    type CommonProofExternalMemoryRequest,
    type CommonProofGenerationCheckpoint,
} from '@sealed-lattice/wasm';

import {
    describeAuthenticatedCheckpointStateStream,
    type CheckpointBoundary,
    type CheckpointOperationIdentity,
    type ExpectedCheckpointBoundary,
} from '../authenticated-checkpoint-store.js';
import type { UntrustedStorageAuthenticator } from '../untrusted-storage-transaction-store.js';

import {
    foundationHashByteLength,
    identifierByteLength,
    maximumCanonicalDataChunkByteLength,
    maximumDeletionBatchRecordCount,
    canonicalCommonProofOutputChunkByteLength,
    maximumCommonProofOutputChunkCount,
    maximumCommonProofOutputByteLength,
    canonicalOutputKeyDomain,
    checkpointStateStreamDomain,
    commonProofGenerationCheckpointOperationKind,
    maximumCheckpointCursorManifestByteLength,
    textEncoder,
    isSafeUnsigned32,
    copyExactBytes,
    bytesEqual,
    bytesToHex,
    deriveCommonProofAttemptLogicalRecordPrefix,
    commonProofApplicationHandoffLogicalRecordKey,
    unsigned32Bytes,
    hexToExactBytes,
    copyCheckpointResumeDescriptor,
    destroyCheckpointResumeDescriptor,
    destroyIdentifierInput,
    allObjectDescriptors,
    destroyExternalMemoryObjectInMemory,
    checkpointEnvironmentBindingHash,
    encodePublicRecord,
    decodePublicRecord,
    closeTransactionAfterFailure,
    validateLimits,
    copyIdentifierInput,
    type CommonProofExternalMemoryIdentifierInput,
    type ExternalMemoryRecordDescriptor,
    type ExternalMemoryObjectState,
    type StagedExternalMemoryRecordChange,
    type ExternalMemoryShadowState,
    type CanonicalOutputChunk,
    type CommonProofBrowserCustodyLimits,
    type CommonProofBrowserCustodyInput,
    type CommonProofCheckpointResumeDescriptor,
    type CommonProofApplicationHandoff,
    type CommonProofCheckpointCustody,
    type CommonProofBrowserCustody,
} from './records.js';

export {
    commonProofApplicationHandoffLogicalRecordKey,
    commonProofApplicationHandoffMarkerRecordByteLength,
    deriveCommonProofAttemptLogicalRecordPrefix,
} from './records.js';
export type {
    CommonProofApplicationHandoff,
    CommonProofBrowserCustody,
    CommonProofCheckpointResumeDescriptor,
} from './records.js';

export const openCommonProofBrowserCustody = (
    input: CommonProofBrowserCustodyInput,
): CommonProofBrowserCustody => {
    if (typeof input !== 'object' || input === null) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'Common-proof browser custody requires a configuration object.',
        );
    }
    const scratchStorage = openClosedWorkerCommonProofScratchStorage(
        input.workerKernel,
    );
    let actionRandomnessCommitment = new Uint8Array(0);
    let commonProofEnvironmentIdentifier = new Uint8Array(0);
    let commonProofRuntimeBindingHash = new Uint8Array(0);
    let proofAttemptLineageIdentifier = new Uint8Array(0);
    let limits: CommonProofBrowserCustodyLimits;
    let attemptLogicalRecordPrefix = '';
    let applicationHandoffLogicalRecordKey = '';
    let latestCheckpointResumeDescriptor:
        | CommonProofCheckpointResumeDescriptor
        | undefined;
    let initialCheckpointOperationIdentity:
        | CheckpointOperationIdentity
        | undefined;
    try {
        actionRandomnessCommitment = copyExactBytes(
            input.actionRandomnessCommitment,
            foundationHashByteLength,
            'Action-randomness commitment',
        );
        commonProofEnvironmentIdentifier = copyExactBytes(
            input.commonProofEnvironmentIdentifier,
            identifierByteLength,
            'Common-proof environment identifier',
        );
        commonProofRuntimeBindingHash = copyExactBytes(
            input.commonProofRuntimeBindingHash,
            foundationHashByteLength,
            'Common-proof runtime-binding hash',
        );
        proofAttemptLineageIdentifier = copyExactBytes(
            input.proofAttemptLineageIdentifier,
            identifierByteLength,
            'Proof-attempt lineage identifier',
        );
        limits = validateLimits(input.limits);
        attemptLogicalRecordPrefix =
            deriveCommonProofAttemptLogicalRecordPrefix({
                commonProofEnvironmentIdentifier,
                commonProofRuntimeBindingHash,
                proofAttemptLineageIdentifier,
            });
        applicationHandoffLogicalRecordKey =
            commonProofApplicationHandoffLogicalRecordKey;
        latestCheckpointResumeDescriptor =
            input.checkpoint !== undefined &&
            'resumeDescriptor' in input.checkpoint
                ? copyCheckpointResumeDescriptor(
                      input.checkpoint.resumeDescriptor,
                  )
                : undefined;
        initialCheckpointOperationIdentity =
            input.checkpoint !== undefined &&
            'operationIdentity' in input.checkpoint
                ? input.checkpoint.operationIdentity
                : undefined;
        if (
            latestCheckpointResumeDescriptor !== undefined &&
            (!bytesEqual(
                latestCheckpointResumeDescriptor.commonProofEnvironmentIdentifier,
                commonProofEnvironmentIdentifier,
            ) ||
                latestCheckpointResumeDescriptor.privateRandomnessStreamAttemptIdentifier ===
                    undefined ||
                !bytesEqual(
                    latestCheckpointResumeDescriptor.privateRandomnessStreamAttemptIdentifier,
                    proofAttemptLineageIdentifier,
                ))
        ) {
            throw new BrowserActionStorageCustodyError(
                'RecordAuthenticationFailed',
                'The resumed common-proof environment or proof-attempt lineage differs from the authenticated checkpoint.',
            );
        }
        if (initialCheckpointOperationIdentity !== undefined) {
            const boundProofAttemptLineageIdentifier =
                initialCheckpointOperationIdentity.privateRandomnessStreamAttemptIdentifier;
            if (
                boundProofAttemptLineageIdentifier === undefined ||
                !bytesEqual(
                    boundProofAttemptLineageIdentifier,
                    proofAttemptLineageIdentifier,
                )
            ) {
                boundProofAttemptLineageIdentifier?.fill(0);
                throw new BrowserActionStorageCustodyError(
                    'RecordAuthenticationFailed',
                    'The reserved checkpoint lineage is not bound to this common-proof attempt.',
                );
            }
            boundProofAttemptLineageIdentifier.fill(0);
        }
    } catch (error) {
        actionRandomnessCommitment?.fill(0);
        commonProofEnvironmentIdentifier?.fill(0);
        commonProofRuntimeBindingHash?.fill(0);
        proofAttemptLineageIdentifier?.fill(0);
        if (latestCheckpointResumeDescriptor !== undefined) {
            destroyCheckpointResumeDescriptor(latestCheckpointResumeDescriptor);
        }
        throw error;
    }
    const objects = new Map<number, ExternalMemoryObjectState>();
    const outputChunks = new Map<number, CanonicalOutputChunk>();
    let externalMemoryByteLength = 0n;
    let externalMemoryRecordCount = 0;
    let outputByteLength = 0;
    let outputSealed = false;
    let outputTerminalChunkIndex: number | undefined;
    let capacityReservationReleased = false;
    let checkpointEvictionCompleted = false;
    let durableProofRecordsDeleted = false;
    let terminalCheckpointLineageIdentifier:
        | Uint8Array<ArrayBuffer>
        | undefined;
    let terminalCheckpointOperationIdentity:
        | CheckpointOperationIdentity
        | undefined;
    let retirementCleanupCompleted = false;
    let applicationHandoffArmed = false;
    let state: 'open' | 'releasing-external-memory' | 'retiring' | 'retired' =
        'open';
    let checkpointOperationIdentity = initialCheckpointOperationIdentity;
    let checkpointRestoreAttempted = false;
    const assertOpen = (): void => {
        if (state !== 'open') {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The common-proof browser custody environment is not open.',
            );
        }
    };

    const preserveCheckpointLineageForTerminalCleanup = (): void => {
        if (
            checkpointEvictionCompleted ||
            terminalCheckpointLineageIdentifier !== undefined
        ) {
            return;
        }
        if (input.checkpoint === undefined) {
            checkpointEvictionCompleted = true;
            return;
        }
        terminalCheckpointOperationIdentity ??= checkpointOperationIdentity;
        const checkpointLineageIdentifier =
            latestCheckpointResumeDescriptor?.checkpointLineageIdentifier ??
            terminalCheckpointOperationIdentity?.checkpointLineageIdentifier;
        if (checkpointLineageIdentifier === undefined) {
            checkpointEvictionCompleted = true;
            return;
        }
        terminalCheckpointLineageIdentifier =
            checkpointLineageIdentifier.slice();
    };

    const permanentlyRetireInMemory = (
        preserveCheckpointForCleanup = true,
    ): void => {
        if (preserveCheckpointForCleanup) {
            preserveCheckpointLineageForTerminalCleanup();
        }
        state = 'retired';
        actionRandomnessCommitment.fill(0);
        commonProofEnvironmentIdentifier.fill(0);
        commonProofRuntimeBindingHash.fill(0);
        proofAttemptLineageIdentifier.fill(0);
        for (const object of objects.values()) {
            destroyExternalMemoryObjectInMemory(object);
        }
        checkpointOperationIdentity = undefined;
        if (latestCheckpointResumeDescriptor !== undefined) {
            destroyCheckpointResumeDescriptor(latestCheckpointResumeDescriptor);
            latestCheckpointResumeDescriptor = undefined;
        }
    };

    const checkpointBoundary = (inputValue: {
        canonicalStateBytes?: Uint8Array;
        commonProofEnvironmentIdentifier: Uint8Array;
        privateRandomCursorManifestBytes: Uint8Array;
        privateRandomnessStreamAttemptIdentifier?: Uint8Array;
        safeBoundaryOrdinal: number;
        stableAttemptBindingHash: Uint8Array;
    }): CheckpointBoundary | ExpectedCheckpointBoundary => {
        if (input.checkpoint === undefined) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'Common-proof checkpoint custody is not configured.',
            );
        }
        const environmentBindingHash = checkpointEnvironmentBindingHash({
            commonProofEnvironmentIdentifier:
                inputValue.commonProofEnvironmentIdentifier,
            commonProofRuntimeBindingHash,
            proofAttemptLineageIdentifier,
        });
        return Object.freeze({
            operationKind: commonProofGenerationCheckpointOperationKind,
            orderedSourceDigests: Object.freeze([
                commonProofRuntimeBindingHash.slice(),
                inputValue.stableAttemptBindingHash.slice(),
                environmentBindingHash,
            ]),
            privateRandomCursorManifestBytes:
                inputValue.privateRandomCursorManifestBytes.slice(),
            ...(inputValue.privateRandomnessStreamAttemptIdentifier ===
            undefined
                ? {}
                : {
                      privateRandomnessStreamAttemptIdentifier:
                          inputValue.privateRandomnessStreamAttemptIdentifier.slice(),
                  }),
            safeBoundaryOrdinal: inputValue.safeBoundaryOrdinal,
            ...(inputValue.canonicalStateBytes === undefined
                ? {}
                : {
                      stateStreamDescriptorBytes:
                          describeAuthenticatedCheckpointStateStream({
                              stateBytes: inputValue.canonicalStateBytes,
                              stateStreamDomain: checkpointStateStreamDomain,
                          }),
                  }),
            stateStreamDomain: checkpointStateStreamDomain,
        });
    };

    const configuredCheckpointCustody:
        | CommonProofCheckpointCustody
        | undefined =
        input.checkpoint === undefined
            ? undefined
            : Object.freeze({
                  publishAuthenticatedCheckpoint: async (
                      checkpoint: CommonProofGenerationCheckpoint,
                  ): Promise<void> => {
                      assertOpen();
                      if (
                          !(
                              checkpoint.canonicalStateBytes instanceof
                              Uint8Array
                          ) ||
                          checkpoint.canonicalStateBytes.byteLength === 0 ||
                          !(
                              checkpoint.stableAttemptBindingHash instanceof
                              Uint8Array
                          ) ||
                          checkpoint.stableAttemptBindingHash.byteLength !==
                              foundationHashByteLength ||
                          !(
                              checkpoint.privateRandomCursorManifestBytes instanceof
                              Uint8Array
                          ) ||
                          checkpoint.privateRandomCursorManifestBytes
                              .byteLength >
                              maximumCheckpointCursorManifestByteLength ||
                          (checkpoint.privateRandomnessStreamAttemptIdentifier !==
                              undefined &&
                              (!(checkpoint.privateRandomnessStreamAttemptIdentifier instanceof
                                  Uint8Array) ||
                                  checkpoint.privateRandomnessStreamAttemptIdentifier
                                      .byteLength !== identifierByteLength)) ||
                          !isSafeUnsigned32(checkpoint.safeBoundaryOrdinal)
                      ) {
                          throw new BrowserActionStorageCustodyError(
                              'InvalidInput',
                              'The common-proof kernel exposed a malformed checkpoint.',
                          );
                      }
                      if (
                          latestCheckpointResumeDescriptor !== undefined &&
                          !bytesEqual(
                              latestCheckpointResumeDescriptor.stableAttemptBindingHash,
                              checkpoint.stableAttemptBindingHash,
                          )
                      ) {
                          throw new BrowserActionStorageCustodyError(
                              'RecordAuthenticationFailed',
                              'A common-proof checkpoint changed its stable attempt binding.',
                          );
                      }
                      const privateRandomCursorManifestBytes = Uint8Array.from(
                          checkpoint.privateRandomCursorManifestBytes,
                      );
                      const privateRandomnessStreamAttemptIdentifier =
                          checkpoint.privateRandomnessStreamAttemptIdentifier?.slice();
                      try {
                          const boundary = checkpointBoundary({
                              canonicalStateBytes:
                                  checkpoint.canonicalStateBytes,
                              commonProofEnvironmentIdentifier,
                              privateRandomCursorManifestBytes,
                              ...(privateRandomnessStreamAttemptIdentifier ===
                              undefined
                                  ? {}
                                  : {
                                        privateRandomnessStreamAttemptIdentifier,
                                    }),
                              safeBoundaryOrdinal:
                                  checkpoint.safeBoundaryOrdinal,
                              stableAttemptBindingHash:
                                  checkpoint.stableAttemptBindingHash,
                          }) as CheckpointBoundary;
                          if (checkpointOperationIdentity === undefined) {
                              throw new BrowserActionStorageCustodyError(
                                  'InvalidState',
                                  'Fresh common-proof checkpoint publication lost its pre-bound lineage identity.',
                              );
                          }
                          await input.checkpoint!.store.publish({
                              boundary,
                              identity: checkpointOperationIdentity,
                              stateChunks: [
                                  checkpoint.canonicalStateBytes.slice(),
                              ],
                          });
                          const nextResumeDescriptor =
                              copyCheckpointResumeDescriptor({
                                  checkpointLineageIdentifier:
                                      checkpointOperationIdentity.checkpointLineageIdentifier,
                                  commonProofEnvironmentIdentifier,
                                  privateRandomCursorManifestBytes,
                                  ...(privateRandomnessStreamAttemptIdentifier ===
                                  undefined
                                      ? {}
                                      : {
                                            privateRandomnessStreamAttemptIdentifier,
                                        }),
                                  safeBoundaryOrdinal:
                                      checkpoint.safeBoundaryOrdinal,
                                  stableAttemptBindingHash:
                                      checkpoint.stableAttemptBindingHash,
                              });
                          if (latestCheckpointResumeDescriptor !== undefined) {
                              destroyCheckpointResumeDescriptor(
                                  latestCheckpointResumeDescriptor,
                              );
                          }
                          latestCheckpointResumeDescriptor =
                              nextResumeDescriptor;
                      } finally {
                          privateRandomCursorManifestBytes.fill(0);
                          privateRandomnessStreamAttemptIdentifier?.fill(0);
                      }
                  },
                  restoreAuthenticatedCheckpointState:
                      async (): Promise<Uint8Array> => {
                          assertOpen();
                          if (
                              checkpointRestoreAttempted ||
                              latestCheckpointResumeDescriptor === undefined
                          ) {
                              throw new BrowserActionStorageCustodyError(
                                  'InvalidState',
                                  'The common-proof checkpoint cannot be restored in its current state.',
                              );
                          }
                          checkpointRestoreAttempted = true;
                          try {
                              const resumeDescriptor =
                                  latestCheckpointResumeDescriptor;
                              const expectedBoundary = checkpointBoundary({
                                  commonProofEnvironmentIdentifier:
                                      resumeDescriptor.commonProofEnvironmentIdentifier,
                                  privateRandomCursorManifestBytes:
                                      resumeDescriptor.privateRandomCursorManifestBytes,
                                  ...(resumeDescriptor.privateRandomnessStreamAttemptIdentifier ===
                                  undefined
                                      ? {}
                                      : {
                                            privateRandomnessStreamAttemptIdentifier:
                                                resumeDescriptor.privateRandomnessStreamAttemptIdentifier,
                                        }),
                                  safeBoundaryOrdinal:
                                      resumeDescriptor.safeBoundaryOrdinal,
                                  stableAttemptBindingHash:
                                      resumeDescriptor.stableAttemptBindingHash,
                              });
                              const resumed =
                                  await input.checkpoint!.store.resume({
                                      checkpointLineageIdentifier:
                                          resumeDescriptor.checkpointLineageIdentifier,
                                      expectedBoundary,
                                  });
                              checkpointOperationIdentity =
                                  resumed.operationIdentity;
                              const restoredChunks: Uint8Array[] = [];
                              try {
                                  await resumed.restoreState(
                                      (chunkIndex, chunkBytes) => {
                                          if (
                                              chunkIndex !==
                                              restoredChunks.length
                                          ) {
                                              throw new BrowserActionStorageCustodyError(
                                                  'RecordAuthenticationFailed',
                                                  'Authenticated common-proof checkpoint chunks are reordered.',
                                              );
                                          }
                                          restoredChunks.push(
                                              chunkBytes.slice(),
                                          );
                                      },
                                  );
                                  const totalByteLength = restoredChunks.reduce(
                                      (sum, chunk) => sum + chunk.byteLength,
                                      0,
                                  );
                                  const restoredState = new Uint8Array(
                                      totalByteLength,
                                  );
                                  let offset = 0;
                                  for (const chunk of restoredChunks) {
                                      restoredState.set(chunk, offset);
                                      offset += chunk.byteLength;
                                  }
                                  return restoredState;
                              } finally {
                                  for (const chunk of restoredChunks) {
                                      chunk.fill(0);
                                  }
                              }
                          } catch (error) {
                              state = 'retiring';
                              const cleanupFailures =
                                  await cleanupTerminalProofAuthority();
                              permanentlyRetireInMemory();
                              if (cleanupFailures.length !== 0) {
                                  throw new BrowserActionStorageCustodyError(
                                      'StorageFailure',
                                      'Common-proof checkpoint restoration failed and durable retirement was incomplete.',
                                      [error, ...cleanupFailures],
                                  );
                              }
                              throw error;
                          }
                      },
              });

    const identifierInput = (inputValue: {
        byteOffset: bigint;
        chunkOrdinal: number;
        objectOrdinal: number;
        recordKind: CommonProofExternalMemoryIdentifierInput['externalMemoryRecordKind'];
    }): CommonProofExternalMemoryIdentifierInput => {
        let environmentIdentifier = new Uint8Array(0);
        let runtimeBindingHash = new Uint8Array(0);
        let attemptLineageIdentifier = new Uint8Array(0);
        try {
            environmentIdentifier = commonProofEnvironmentIdentifier.slice();
            runtimeBindingHash = commonProofRuntimeBindingHash.slice();
            attemptLineageIdentifier = proofAttemptLineageIdentifier.slice();
            return Object.freeze({
                commonProofEnvironmentIdentifier: environmentIdentifier,
                commonProofRuntimeBindingHash: runtimeBindingHash,
                externalMemoryByteOffset: inputValue.byteOffset,
                externalMemoryChunkOrdinal: inputValue.chunkOrdinal,
                externalMemoryObjectOrdinal: inputValue.objectOrdinal,
                externalMemoryRecordKind: inputValue.recordKind,
                proofAttemptLineageIdentifier: attemptLineageIdentifier,
                recordType: 'commonProofExternalMemory',
            });
        } catch (error) {
            environmentIdentifier.fill(0);
            runtimeBindingHash.fill(0);
            attemptLineageIdentifier.fill(0);
            throw error;
        }
    };

    const createDescriptor = async (
        recordInput: CommonProofExternalMemoryIdentifierInput,
        protection: ExternalMemoryRecordDescriptor['protection'],
    ): Promise<ExternalMemoryRecordDescriptor> => {
        let identifier: Uint8Array = new Uint8Array(0);
        try {
            identifier =
                await scratchStorage.deriveRecordIdentifier(recordInput);
            if (
                !(identifier instanceof Uint8Array) ||
                identifier.byteLength !== foundationHashByteLength
            ) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The worker kernel returned an invalid common-proof external-memory identifier.',
                );
            }
            return Object.freeze({
                identifierInput: copyIdentifierInput(recordInput),
                logicalRecordKey: `${attemptLogicalRecordPrefix}external-memory/${bytesToHex(identifier)}`,
                protection,
            });
        } finally {
            identifier.fill(0);
            destroyIdentifierInput(recordInput);
        }
    };

    const openSecretRecord = async (
        descriptor: ExternalMemoryRecordDescriptor,
        canonicalEnvelope: Uint8Array,
    ): Promise<Uint8Array<ArrayBuffer>> => {
        const commitmentCopy = actionRandomnessCommitment.slice();
        const envelopeCopy = canonicalEnvelope.slice();
        const identifierInputCopy = copyIdentifierInput(
            descriptor.identifierInput,
        );
        try {
            const plaintext = await scratchStorage.openRecord({
                actionRandomnessCommitment: commitmentCopy,
                envelope: envelopeCopy,
                identifierInput: identifierInputCopy,
            });
            if (!(plaintext instanceof Uint8Array)) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The worker kernel returned malformed common-proof external-memory plaintext.',
                );
            }
            const ownedPlaintext = plaintext.slice();
            plaintext.fill(0);
            return ownedPlaintext;
        } catch (error) {
            if (error instanceof BrowserActionStorageCustodyError) {
                throw error;
            }
            throw new BrowserActionStorageCustodyError(
                'RecordAuthenticationFailed',
                'A secret common-proof external-memory record could not be opened.',
                error,
            );
        } finally {
            commitmentCopy.fill(0);
            envelopeCopy.fill(0);
            destroyIdentifierInput(identifierInputCopy);
        }
    };

    const encodeRecord = async (
        descriptor: ExternalMemoryRecordDescriptor,
        payload: Uint8Array,
    ): Promise<Uint8Array<ArrayBuffer>> => {
        if (descriptor.protection === 'public-integrity') {
            return encodePublicRecord(descriptor.logicalRecordKey, payload);
        }
        const commitmentCopy = actionRandomnessCommitment.slice();
        const identifierInputCopy = copyIdentifierInput(
            descriptor.identifierInput,
        );
        const plaintextCopy = payload.slice();
        try {
            const envelope = await scratchStorage.sealRecord({
                actionRandomnessCommitment: commitmentCopy,
                identifierInput: identifierInputCopy,
                plaintext: plaintextCopy,
            });
            if (
                !(envelope instanceof Uint8Array) ||
                envelope.byteLength === 0
            ) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The worker kernel returned a malformed secret common-proof external-memory envelope.',
                );
            }
            const ownedEnvelope = envelope.slice();
            envelope.fill(0);
            return ownedEnvelope;
        } finally {
            commitmentCopy.fill(0);
            destroyIdentifierInput(identifierInputCopy);
            plaintextCopy.fill(0);
        }
    };

    const decodeRecord = async (
        descriptor: ExternalMemoryRecordDescriptor,
        storedBytes: Uint8Array,
    ): Promise<Uint8Array<ArrayBuffer>> =>
        descriptor.protection === 'public-integrity'
            ? decodePublicRecord(descriptor.logicalRecordKey, storedBytes)
            : openSecretRecord(descriptor, storedBytes);

    const authenticateRecord =
        (
            descriptor: ExternalMemoryRecordDescriptor,
            expectedPayload?: Uint8Array,
        ): UntrustedStorageAuthenticator =>
        async ({ bytes, logicalRecordKey }) => {
            if (logicalRecordKey !== descriptor.logicalRecordKey) {
                throw new BrowserActionStorageCustodyError(
                    'RecordAuthenticationFailed',
                    'A common-proof record was returned under the wrong logical key.',
                );
            }
            const payload = await decodeRecord(descriptor, bytes);
            try {
                if (
                    expectedPayload !== undefined &&
                    !bytesEqual(payload, expectedPayload)
                ) {
                    throw new BrowserActionStorageCustodyError(
                        'RecordAuthenticationFailed',
                        'A common-proof record does not contain the expected bytes.',
                    );
                }
            } finally {
                payload.fill(0);
            }
        };

    const readStoredRecord = async (
        descriptor: ExternalMemoryRecordDescriptor,
    ): Promise<
        | Readonly<{
              payload: Uint8Array<ArrayBuffer>;
              storedBytes: Uint8Array<ArrayBuffer>;
          }>
        | undefined
    > => {
        let authenticatedPayload: Uint8Array<ArrayBuffer> | undefined;
        const storedBytes = await input.store.readAuthenticated({
            authenticate: async ({ bytes, logicalRecordKey }) => {
                if (logicalRecordKey !== descriptor.logicalRecordKey) {
                    throw new BrowserActionStorageCustodyError(
                        'RecordAuthenticationFailed',
                        'A common-proof record was returned under the wrong logical key.',
                    );
                }
                authenticatedPayload = await decodeRecord(descriptor, bytes);
            },
            logicalRecordKey: descriptor.logicalRecordKey,
        });
        if (storedBytes === undefined) {
            authenticatedPayload?.fill(0);
            return undefined;
        }
        if (authenticatedPayload === undefined) {
            storedBytes.fill(0);
            throw new BrowserActionStorageCustodyError(
                'RecordAuthenticationFailed',
                'A common-proof record was not authenticated during its read.',
            );
        }
        const ownedStoredBytes = Uint8Array.from(storedBytes);
        storedBytes.fill(0);
        return Object.freeze({
            payload: authenticatedPayload,
            storedBytes: ownedStoredBytes,
        });
    };

    const readRecord = async (
        descriptor: ExternalMemoryRecordDescriptor,
    ): Promise<Uint8Array<ArrayBuffer>> => {
        const storedRecord = await readStoredRecord(descriptor);
        if (storedRecord === undefined) {
            throw new BrowserActionStorageCustodyError(
                'RecordAuthenticationFailed',
                'A required common-proof record is unavailable.',
            );
        }
        storedRecord.storedBytes.fill(0);
        return storedRecord.payload;
    };

    const clearStagedRecordChange = (
        change: StagedExternalMemoryRecordChange,
    ): void => {
        if (change.kind === 'write') {
            change.write.encodedRecord?.fill(0);
            change.write.payload.fill(0);
            change.write.expectedCurrentValue?.fill(0);
            return;
        }
    };

    const clearShadowChanges = (shadow: ExternalMemoryShadowState): void => {
        for (const change of shadow.changes.values()) {
            clearStagedRecordChange(change);
        }
        shadow.changes.clear();
    };

    const stageRecordWrite = async (
        shadow: ExternalMemoryShadowState,
        descriptor: ExternalMemoryRecordDescriptor,
        payload: Uint8Array,
    ): Promise<void> => {
        if (shadow.changes.has(descriptor.logicalRecordKey)) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'A common-proof transaction changes one record more than once.',
            );
        }
        let encodedRecord: Uint8Array<ArrayBuffer> | undefined;
        let expectedCurrentValue: Uint8Array<ArrayBuffer> | null = null;
        if (shadow.replay) {
            const storedRecord = await readStoredRecord(descriptor);
            if (storedRecord !== undefined) {
                try {
                    if (!bytesEqual(storedRecord.payload, payload)) {
                        throw new BrowserActionStorageCustodyError(
                            'RecordAuthenticationFailed',
                            'A replayed common-proof record differs from its committed bytes.',
                        );
                    }
                    encodedRecord = storedRecord.storedBytes.slice();
                    expectedCurrentValue = storedRecord.storedBytes.slice();
                } finally {
                    storedRecord.payload.fill(0);
                    storedRecord.storedBytes.fill(0);
                }
            } else {
                encodedRecord = undefined;
            }
        } else {
            encodedRecord = undefined;
        }
        shadow.changes.set(
            descriptor.logicalRecordKey,
            Object.freeze({
                kind: 'write',
                write: {
                    descriptor,
                    encodedRecord,
                    expectedCurrentValue,
                    payload: payload.slice(),
                },
            }),
        );
    };

    const stageRecordDeletion = (
        shadow: ExternalMemoryShadowState,
        descriptor: ExternalMemoryRecordDescriptor,
    ): void => {
        const stagedChange = shadow.changes.get(descriptor.logicalRecordKey);
        if (stagedChange?.kind === 'delete') {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'A common-proof transaction deletes one record more than once.',
            );
        }
        if (stagedChange?.kind === 'write') {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'A common-proof transaction cannot write and delete one record.',
            );
        }
        shadow.changes.set(
            descriptor.logicalRecordKey,
            Object.freeze({
                deletion: { descriptor },
                kind: 'delete',
            }),
        );
    };

    const readShadowRecord = async (
        shadow: ExternalMemoryShadowState,
        descriptor: ExternalMemoryRecordDescriptor,
    ): Promise<Uint8Array<ArrayBuffer>> => {
        const stagedChange = shadow.changes.get(descriptor.logicalRecordKey);
        if (stagedChange?.kind === 'write') {
            return stagedChange.write.payload.slice();
        }
        if (stagedChange?.kind === 'delete') {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'A common-proof transaction read a record after deleting it.',
            );
        }
        return readRecord(descriptor);
    };

    const commitShadowChanges = async (
        shadow: ExternalMemoryShadowState,
    ): Promise<void> => {
        if (shadow.changes.size === 0) {
            return;
        }
        for (const change of shadow.changes.values()) {
            if (
                change.kind === 'write' &&
                change.write.encodedRecord === undefined
            ) {
                change.write.encodedRecord = await encodeRecord(
                    change.write.descriptor,
                    change.write.payload,
                );
            }
        }
        const changes = [...shadow.changes.values()];
        const changeBatches: readonly (readonly StagedExternalMemoryRecordChange[])[] =
            changes.every((change) => change.kind === 'delete')
                ? Array.from(
                      {
                          length: Math.ceil(
                              changes.length / maximumDeletionBatchRecordCount,
                          ),
                      },
                      (_unused, batchIndex) =>
                          changes.slice(
                              batchIndex * maximumDeletionBatchRecordCount,
                              (batchIndex + 1) *
                                  maximumDeletionBatchRecordCount,
                          ),
                  )
                : [changes];
        let committedBatchCount = 0;
        for (const changeBatch of changeBatches) {
            const transaction = await input.store.beginTransaction({
                lifetimeMilliseconds: limits.transactionLifetimeMilliseconds,
            });
            let commitAttempted = false;
            try {
                for (const change of changeBatch) {
                    if (change.kind === 'delete') {
                        await transaction.stageDeletion(
                            change.deletion.descriptor.logicalRecordKey,
                        );
                        continue;
                    }
                    const encodedRecord = change.write.encodedRecord;
                    if (encodedRecord === undefined) {
                        throw new BrowserActionStorageCustodyError(
                            'InvalidState',
                            'A staged common-proof record is missing its canonical storage bytes.',
                        );
                    }
                    const lease = await transaction.issueWriteLease({
                        declaredByteLength: encodedRecord.byteLength,
                        expectedCurrentValue: change.write.expectedCurrentValue,
                        logicalRecordKey:
                            change.write.descriptor.logicalRecordKey,
                    });
                    await lease.write(encodedRecord);
                    await lease.seal(
                        authenticateRecord(
                            change.write.descriptor,
                            change.write.payload,
                        ),
                    );
                }
                commitAttempted = true;
                await transaction.commit();
                committedBatchCount += 1;
            } catch (error) {
                try {
                    await transaction.closeAfterFailure();
                } catch (cleanupError) {
                    permanentlyRetireInMemory();
                    throw new BrowserActionStorageCustodyError(
                        'StorageFailure',
                        'A common-proof transaction failed and could not clean up.',
                        { cleanupError, operationError: error },
                    );
                }
                if (commitAttempted || committedBatchCount > 0) {
                    permanentlyRetireInMemory();
                }
                throw error;
            }
            try {
                for (const change of changeBatch) {
                    if (change.kind === 'delete') {
                        const remaining = await readStoredRecord(
                            change.deletion.descriptor,
                        );
                        if (remaining !== undefined) {
                            remaining.payload.fill(0);
                            remaining.storedBytes.fill(0);
                            throw new BrowserActionStorageCustodyError(
                                'RecordAuthenticationFailed',
                                'A deleted common-proof record remained visible during exact readback.',
                            );
                        }
                        continue;
                    }
                    const committed = await readStoredRecord(
                        change.write.descriptor,
                    );
                    if (committed === undefined) {
                        throw new BrowserActionStorageCustodyError(
                            'RecordAuthenticationFailed',
                            'A committed common-proof record is unavailable during exact readback.',
                        );
                    }
                    try {
                        const encodedRecord = change.write.encodedRecord;
                        if (
                            encodedRecord === undefined ||
                            !bytesEqual(committed.storedBytes, encodedRecord) ||
                            !bytesEqual(committed.payload, change.write.payload)
                        ) {
                            throw new BrowserActionStorageCustodyError(
                                'RecordAuthenticationFailed',
                                'A common-proof record changed during exact commit readback.',
                            );
                        }
                    } finally {
                        committed.payload.fill(0);
                        committed.storedBytes.fill(0);
                    }
                }
            } catch (error) {
                permanentlyRetireInMemory();
                throw error;
            }
        }
    };

    const deleteLogicalRecord = async (
        logicalRecordKey: string,
    ): Promise<void> => {
        const transaction = await input.store.beginTransaction({
            lifetimeMilliseconds: limits.transactionLifetimeMilliseconds,
        });
        try {
            await transaction.stageDeletion(logicalRecordKey);
            await transaction.commit();
        } catch (error) {
            return await closeTransactionAfterFailure(transaction, error);
        }
    };

    const deleteObjectRecords = async (
        object: ExternalMemoryObjectState,
    ): Promise<void> => {
        for (const descriptor of allObjectDescriptors(object)) {
            await deleteLogicalRecord(descriptor.logicalRecordKey);
        }
    };

    const requireObject = (
        objectMap: ReadonlyMap<number, ExternalMemoryObjectState>,
        objectOrdinal: number,
    ): ExternalMemoryObjectState => {
        const object = objectMap.get(objectOrdinal);
        if (object === undefined) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'A common-proof external-memory operation names an unavailable object.',
            );
        }
        return object;
    };

    const reserveRecord = (
        shadow: ExternalMemoryShadowState,
        payloadByteLength: number,
    ): void => {
        if (
            shadow.recordCount >= limits.maximumExternalMemoryRecordCount ||
            shadow.byteLength + BigInt(payloadByteLength) >
                limits.maximumExternalMemoryByteLength
        ) {
            throw new BrowserActionStorageCustodyError(
                'StorageFailure',
                'Common-proof external-memory custody exceeds its fixed quota.',
            );
        }
        shadow.recordCount += 1;
        shadow.byteLength += BigInt(payloadByteLength);
    };

    const createObject = async (
        operation: Extract<
            CommonProofExternalMemoryRequest['operations'][number],
            { readonly operationKind: 'create' }
        >,
        shadow: ExternalMemoryShadowState,
    ): Promise<void> => {
        if (
            shadow.objects.has(operation.objectOrdinal) ||
            shadow.objects.size >= limits.maximumExternalMemoryObjectCount ||
            operation.exactByteLength > limits.maximumExternalMemoryByteLength
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'A common-proof create operation conflicts with custody state or quota.',
            );
        }
        const headerPayload = new Uint8Array(9);
        headerPayload[0] = operation.protection === 'public-integrity' ? 1 : 2;
        new DataView(headerPayload.buffer).setBigUint64(
            1,
            operation.exactByteLength,
            true,
        );
        reserveRecord(shadow, headerPayload.byteLength);
        const header = await createDescriptor(
            identifierInput({
                byteOffset: 0n,
                chunkOrdinal: 0,
                objectOrdinal: operation.objectOrdinal,
                recordKind: 'object-header',
            }),
            operation.protection,
        );
        shadow.createdDescriptors.add(header);
        try {
            await stageRecordWrite(shadow, header, headerPayload);
        } finally {
            headerPayload.fill(0);
        }
        shadow.objects.set(operation.objectOrdinal, {
            appendedByteLength: 0n,
            chunks: [],
            exactByteLength: operation.exactByteLength,
            header,
            nextChunkOrdinal: 1,
            protection: operation.protection,
        });
    };

    const appendObject = async (
        operation: Extract<
            CommonProofExternalMemoryRequest['operations'][number],
            { readonly operationKind: 'append' }
        >,
        shadow: ExternalMemoryShadowState,
    ): Promise<void> => {
        const object = requireObject(shadow.objects, operation.objectOrdinal);
        const remainingByteLength =
            object.exactByteLength - object.appendedByteLength;
        const expectedAppendByteLength = Number(
            remainingByteLength < BigInt(maximumCanonicalDataChunkByteLength)
                ? remainingByteLength
                : BigInt(maximumCanonicalDataChunkByteLength),
        );
        if (
            object.sealMarker !== undefined ||
            operation.expectedOffset !== object.appendedByteLength ||
            operation.bytes.byteLength !== expectedAppendByteLength ||
            object.appendedByteLength + BigInt(operation.bytes.byteLength) >
                object.exactByteLength
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'A common-proof append operation violates the object lifecycle.',
            );
        }
        let sourceOffset = 0;
        while (sourceOffset < operation.bytes.byteLength) {
            const chunkByteLength = Math.min(
                maximumCanonicalDataChunkByteLength,
                operation.bytes.byteLength - sourceOffset,
            );
            const chunkBytes = operation.bytes.slice(
                sourceOffset,
                sourceOffset + chunkByteLength,
            );
            const byteOffset = object.appendedByteLength + BigInt(sourceOffset);
            const chunkOrdinal = object.nextChunkOrdinal;
            if (!isSafeUnsigned32(chunkOrdinal)) {
                chunkBytes.fill(0);
                throw new BrowserActionStorageCustodyError(
                    'StorageFailure',
                    'Common-proof external-memory chunk ordinals are exhausted.',
                );
            }
            reserveRecord(shadow, chunkByteLength);
            const descriptor = await createDescriptor(
                identifierInput({
                    byteOffset,
                    chunkOrdinal,
                    objectOrdinal: operation.objectOrdinal,
                    recordKind: 'data-chunk',
                }),
                object.protection,
            );
            shadow.createdDescriptors.add(descriptor);
            try {
                await stageRecordWrite(shadow, descriptor, chunkBytes);
            } finally {
                chunkBytes.fill(0);
            }
            object.chunks.push({
                byteLength: chunkByteLength,
                byteOffset,
                descriptor,
            });
            object.nextChunkOrdinal += 1;
            sourceOffset += chunkByteLength;
        }
        object.appendedByteLength += BigInt(operation.bytes.byteLength);
    };

    const sealObject = async (
        operation: Extract<
            CommonProofExternalMemoryRequest['operations'][number],
            { readonly operationKind: 'seal' }
        >,
        shadow: ExternalMemoryShadowState,
    ): Promise<void> => {
        const object = requireObject(shadow.objects, operation.objectOrdinal);
        if (
            object.sealMarker !== undefined ||
            object.appendedByteLength !== object.exactByteLength ||
            !isSafeUnsigned32(object.nextChunkOrdinal)
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'A common-proof seal operation violates the object lifecycle.',
            );
        }
        reserveRecord(shadow, 0);
        const sealMarker = await createDescriptor(
            identifierInput({
                byteOffset: object.exactByteLength,
                chunkOrdinal: object.nextChunkOrdinal,
                objectOrdinal: operation.objectOrdinal,
                recordKind: 'seal-marker',
            }),
            object.protection,
        );
        shadow.createdDescriptors.add(sealMarker);
        await stageRecordWrite(shadow, sealMarker, new Uint8Array(0));
        object.nextChunkOrdinal += 1;
        object.sealMarker = sealMarker;
    };

    const readObject = async (
        operation: Extract<
            CommonProofExternalMemoryRequest['operations'][number],
            { readonly operationKind: 'read' }
        >,
        shadow: ExternalMemoryShadowState,
    ): Promise<CommonProofExternalMemoryReadResult> => {
        const object = requireObject(shadow.objects, operation.objectOrdinal);
        const readEnd = operation.offset + BigInt(operation.byteLength);
        if (
            object.sealMarker === undefined ||
            readEnd > object.exactByteLength
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'A common-proof read operation violates the sealed object extent.',
            );
        }
        const result = new Uint8Array(operation.byteLength);
        let copiedByteLength = 0;
        try {
            for (const chunk of object.chunks) {
                const chunkEnd = chunk.byteOffset + BigInt(chunk.byteLength);
                if (
                    chunkEnd <= operation.offset ||
                    chunk.byteOffset >= readEnd
                ) {
                    continue;
                }
                const overlapStart =
                    chunk.byteOffset > operation.offset
                        ? chunk.byteOffset
                        : operation.offset;
                const overlapEnd = chunkEnd < readEnd ? chunkEnd : readEnd;
                const sourceStart = Number(overlapStart - chunk.byteOffset);
                const overlapByteLength = Number(overlapEnd - overlapStart);
                const destinationStart = Number(
                    overlapStart - operation.offset,
                );
                const chunkBytes = await readShadowRecord(
                    shadow,
                    chunk.descriptor,
                );
                try {
                    if (chunkBytes.byteLength !== chunk.byteLength) {
                        throw new BrowserActionStorageCustodyError(
                            'RecordAuthenticationFailed',
                            'A common-proof external-memory chunk has the wrong length.',
                        );
                    }
                    result.set(
                        chunkBytes.subarray(
                            sourceStart,
                            sourceStart + overlapByteLength,
                        ),
                        destinationStart,
                    );
                } finally {
                    chunkBytes.fill(0);
                }
                copiedByteLength += overlapByteLength;
            }
            if (copiedByteLength !== operation.byteLength) {
                throw new BrowserActionStorageCustodyError(
                    'RecordAuthenticationFailed',
                    'Common-proof external-memory chunks do not cover the requested range.',
                );
            }
            return Object.freeze({
                bytes: result,
                objectOrdinal: operation.objectOrdinal,
                offset: operation.offset,
                operationIndex: operation.operationIndex,
            });
        } catch (error) {
            result.fill(0);
            throw error;
        }
    };

    const deleteObject = (
        shadow: ExternalMemoryShadowState,
        objectOrdinal: number,
    ): void => {
        const object = requireObject(shadow.objects, objectOrdinal);
        for (const descriptor of allObjectDescriptors(object)) {
            stageRecordDeletion(shadow, descriptor);
        }
        shadow.recordCount -= allObjectDescriptors(object).length;
        shadow.byteLength -= object.appendedByteLength + 9n;
        shadow.objects.delete(objectOrdinal);
    };

    const executeTransaction = async (
        request: CommonProofExternalMemoryRequest,
        replay: boolean,
    ): Promise<readonly CommonProofExternalMemoryReadResult[]> => {
        assertOpen();
        const firstOperationKind = request.operations[0]?.operationKind;
        if (
            firstOperationKind === undefined ||
            (request.operations.length > 1 &&
                (firstOperationKind !== 'delete' ||
                    request.operations.some(
                        (operation) => operation.operationKind !== 'delete',
                    )))
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'A common-proof request does not use the fixed executor transaction grammar.',
            );
        }
        if (
            !bytesEqual(
                request.runtimeBindingHash,
                commonProofRuntimeBindingHash,
            )
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'A common-proof request belongs to another runtime binding.',
            );
        }
        const previousDescriptors = new Set(
            [...objects.values()].flatMap((object) =>
                allObjectDescriptors(object),
            ),
        );
        const shadow: ExternalMemoryShadowState = {
            byteLength: externalMemoryByteLength,
            changes: new Map(),
            createdDescriptors: new Set(),
            objects: new Map(
                [...objects].map(([objectOrdinal, object]) => [
                    objectOrdinal,
                    {
                        ...object,
                        chunks: [...object.chunks],
                    },
                ]),
            ),
            recordCount: externalMemoryRecordCount,
            replay,
        };
        const readResults: CommonProofExternalMemoryReadResult[] = [];
        try {
            for (const operation of request.operations) {
                switch (operation.operationKind) {
                    case 'create':
                        await createObject(operation, shadow);
                        break;
                    case 'append':
                        await appendObject(operation, shadow);
                        break;
                    case 'seal':
                        await sealObject(operation, shadow);
                        break;
                    case 'read':
                        readResults.push(await readObject(operation, shadow));
                        break;
                    case 'delete':
                        deleteObject(shadow, operation.objectOrdinal);
                        break;
                }
            }
            await commitShadowChanges(shadow);
            const retainedDescriptors = new Set(
                [...shadow.objects.values()].flatMap((object) =>
                    allObjectDescriptors(object),
                ),
            );
            for (const descriptor of previousDescriptors) {
                if (!retainedDescriptors.has(descriptor)) {
                    destroyIdentifierInput(descriptor.identifierInput);
                }
            }
            for (const descriptor of shadow.createdDescriptors) {
                if (!retainedDescriptors.has(descriptor)) {
                    destroyIdentifierInput(descriptor.identifierInput);
                }
            }
            objects.clear();
            for (const [objectOrdinal, object] of shadow.objects) {
                objects.set(objectOrdinal, object);
            }
            externalMemoryByteLength = shadow.byteLength;
            externalMemoryRecordCount = shadow.recordCount;
            shadow.createdDescriptors.clear();
            return Object.freeze(readResults);
        } catch (error) {
            for (const readResult of readResults) {
                readResult.bytes.fill(0);
            }
            for (const descriptor of shadow.createdDescriptors) {
                destroyIdentifierInput(descriptor.identifierInput);
            }
            shadow.createdDescriptors.clear();
            throw error;
        } finally {
            clearShadowChanges(shadow);
        }
    };

    const outputLogicalRecordKey = (chunkIndex: number): string => {
        const hash = shake256.create({ dkLen: foundationHashByteLength });
        try {
            const domainBytes = textEncoder.encode(canonicalOutputKeyDomain);
            hash.update(unsigned32Bytes(domainBytes.byteLength));
            hash.update(domainBytes);
            hash.update(commonProofEnvironmentIdentifier);
            hash.update(commonProofRuntimeBindingHash);
            hash.update(proofAttemptLineageIdentifier);
            hash.update(unsigned32Bytes(chunkIndex));
            return `${attemptLogicalRecordPrefix}canonical-output/${bytesToHex(hash.digest())}`;
        } finally {
            hash.destroy();
        }
    };

    const readStoredOutputChunk = async (
        chunkIndex: number,
    ): Promise<
        | Readonly<{
              logicalRecordKey: string;
              payload: Uint8Array<ArrayBuffer>;
              storedBytes: Uint8Array<ArrayBuffer>;
          }>
        | undefined
    > => {
        const logicalRecordKey = outputLogicalRecordKey(chunkIndex);
        let payload: Uint8Array<ArrayBuffer> | undefined;
        const storedBytes = await input.store.readAuthenticated({
            authenticate: ({ bytes, logicalRecordKey: observedKey }) => {
                if (observedKey !== logicalRecordKey) {
                    throw new BrowserActionStorageCustodyError(
                        'RecordAuthenticationFailed',
                        'A common-proof output record was returned under the wrong key.',
                    );
                }
                payload = decodePublicRecord(logicalRecordKey, bytes);
            },
            logicalRecordKey,
        });
        if (storedBytes === undefined) {
            payload?.fill(0);
            return undefined;
        }
        if (payload === undefined) {
            storedBytes.fill(0);
            throw new BrowserActionStorageCustodyError(
                'RecordAuthenticationFailed',
                'A common-proof output record was not authenticated during its read.',
            );
        }
        const ownedStoredBytes = Uint8Array.from(storedBytes);
        storedBytes.fill(0);
        return Object.freeze({
            logicalRecordKey,
            payload,
            storedBytes: ownedStoredBytes,
        });
    };

    const rebuildCanonicalOutputPrefix = async (
        nextChunkIndex: number,
    ): Promise<void> => {
        if (outputChunks.size === nextChunkIndex) {
            return;
        }
        if (
            latestCheckpointResumeDescriptor === undefined ||
            !checkpointRestoreAttempted ||
            nextChunkIndex < outputChunks.size
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'A common-proof output chunk is outside the authenticated resume prefix.',
            );
        }
        const rebuiltPrefix: CanonicalOutputChunk[] = [];
        let rebuiltByteLength = 0;
        try {
            while (outputChunks.size + rebuiltPrefix.length < nextChunkIndex) {
                const prefixChunkIndex =
                    outputChunks.size + rebuiltPrefix.length;
                const existing = await readStoredOutputChunk(prefixChunkIndex);
                if (existing === undefined) {
                    throw new BrowserActionStorageCustodyError(
                        'RecordAuthenticationFailed',
                        'The authenticated common-proof output prefix is incomplete.',
                    );
                }
                try {
                    if (
                        existing.payload.byteLength !==
                        canonicalCommonProofOutputChunkByteLength
                    ) {
                        throw new BrowserActionStorageCustodyError(
                            'RecordAuthenticationFailed',
                            'A nonterminal common-proof output chunk has the wrong canonical length.',
                        );
                    }
                    rebuiltPrefix.push({
                        byteLength: existing.payload.byteLength,
                        logicalRecordKey: existing.logicalRecordKey,
                    });
                    rebuiltByteLength += existing.payload.byteLength;
                } finally {
                    existing.payload.fill(0);
                    existing.storedBytes.fill(0);
                }
            }
        } catch (error) {
            permanentlyRetireInMemory();
            throw error;
        }
        for (const chunk of rebuiltPrefix) {
            outputChunks.set(outputChunks.size, chunk);
        }
        outputByteLength += rebuiltByteLength;
    };

    const outputStore: CommonProofCanonicalOutputStore = Object.freeze({
        commitChunk: async (chunkIndex, chunkBytes) => {
            assertOpen();
            if (
                outputSealed ||
                !isSafeUnsigned32(chunkIndex) ||
                chunkIndex >= maximumCommonProofOutputChunkCount ||
                !(chunkBytes instanceof Uint8Array) ||
                chunkBytes.byteLength === 0 ||
                chunkBytes.byteLength >
                    canonicalCommonProofOutputChunkByteLength ||
                outputTerminalChunkIndex !== undefined ||
                outputByteLength + chunkBytes.byteLength >
                    maximumCommonProofOutputByteLength
            ) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'A common-proof canonical-output chunk is malformed or out of order.',
                );
            }
            await rebuildCanonicalOutputPrefix(chunkIndex);
            if (chunkIndex !== outputChunks.size) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'A common-proof canonical-output chunk is out of order.',
                );
            }
            const logicalRecordKey = outputLogicalRecordKey(chunkIndex);
            const record = encodePublicRecord(logicalRecordKey, chunkBytes);
            const existing = await readStoredOutputChunk(chunkIndex);
            if (existing !== undefined) {
                try {
                    if (
                        latestCheckpointResumeDescriptor === undefined ||
                        !checkpointRestoreAttempted ||
                        !bytesEqual(existing.payload, chunkBytes) ||
                        !bytesEqual(existing.storedBytes, record)
                    ) {
                        permanentlyRetireInMemory();
                        throw new BrowserActionStorageCustodyError(
                            'RecordAuthenticationFailed',
                            'An existing common-proof output chunk differs from the authenticated resumed bytes.',
                        );
                    }
                    outputChunks.set(chunkIndex, {
                        byteLength: chunkBytes.byteLength,
                        logicalRecordKey,
                    });
                    outputByteLength += chunkBytes.byteLength;
                    if (
                        chunkBytes.byteLength <
                        canonicalCommonProofOutputChunkByteLength
                    ) {
                        outputTerminalChunkIndex = chunkIndex;
                    }
                    return;
                } finally {
                    existing.payload.fill(0);
                    existing.storedBytes.fill(0);
                    record.fill(0);
                }
            }
            const transaction = await input.store.beginTransaction({
                lifetimeMilliseconds: limits.transactionLifetimeMilliseconds,
            });
            let commitAttempted = false;
            try {
                const lease = await transaction.issueWriteLease({
                    declaredByteLength: record.byteLength,
                    expectedCurrentValue: null,
                    logicalRecordKey,
                });
                await lease.write(record);
                await lease.seal(({ bytes }) => {
                    const opened = decodePublicRecord(logicalRecordKey, bytes);
                    try {
                        if (!bytesEqual(opened, chunkBytes)) {
                            throw new BrowserActionStorageCustodyError(
                                'RecordAuthenticationFailed',
                                'A staged common-proof output chunk differs from the kernel bytes.',
                            );
                        }
                    } finally {
                        opened.fill(0);
                    }
                });
                commitAttempted = true;
                await transaction.commit();
            } catch (error) {
                try {
                    await transaction.closeAfterFailure();
                } catch (cleanupError) {
                    throw new BrowserActionStorageCustodyError(
                        'StorageFailure',
                        'A common-proof output transaction failed and could not clean up.',
                        { cleanupError, operationError: error },
                    );
                }
                if (commitAttempted) {
                    permanentlyRetireInMemory();
                }
                throw error;
            } finally {
                record.fill(0);
            }
            try {
                const committed = await readStoredOutputChunk(chunkIndex);
                if (committed === undefined) {
                    throw new BrowserActionStorageCustodyError(
                        'RecordAuthenticationFailed',
                        'A committed common-proof output chunk is unavailable during readback.',
                    );
                }
                try {
                    const expectedRecord = encodePublicRecord(
                        logicalRecordKey,
                        chunkBytes,
                    );
                    try {
                        if (
                            !bytesEqual(committed.payload, chunkBytes) ||
                            !bytesEqual(committed.storedBytes, expectedRecord)
                        ) {
                            throw new BrowserActionStorageCustodyError(
                                'RecordAuthenticationFailed',
                                'A committed common-proof output chunk differs during exact readback.',
                            );
                        }
                    } finally {
                        expectedRecord.fill(0);
                    }
                } finally {
                    committed.payload.fill(0);
                    committed.storedBytes.fill(0);
                }
            } catch (error) {
                permanentlyRetireInMemory();
                throw error;
            }
            outputChunks.set(chunkIndex, {
                byteLength: chunkBytes.byteLength,
                logicalRecordKey,
            });
            outputByteLength += chunkBytes.byteLength;
            if (
                chunkBytes.byteLength <
                canonicalCommonProofOutputChunkByteLength
            ) {
                outputTerminalChunkIndex = chunkIndex;
            }
        },
        readChunk: async (chunkIndex, exactByteLength) => {
            assertOpen();
            const chunk = outputChunks.get(chunkIndex);
            if (chunk === undefined || chunk.byteLength !== exactByteLength) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'A common-proof output read names the wrong chunk extent.',
                );
            }
            let opened: Uint8Array<ArrayBuffer> | undefined;
            const record = await input.store.readAuthenticated({
                authenticate: ({ bytes }) => {
                    opened = decodePublicRecord(chunk.logicalRecordKey, bytes);
                },
                logicalRecordKey: chunk.logicalRecordKey,
            });
            record?.fill(0);
            if (record === undefined || opened === undefined) {
                throw new BrowserActionStorageCustodyError(
                    'RecordAuthenticationFailed',
                    'A common-proof output chunk is missing.',
                );
            }
            if (opened.byteLength !== exactByteLength) {
                opened.fill(0);
                throw new BrowserActionStorageCustodyError(
                    'RecordAuthenticationFailed',
                    'A common-proof output chunk changed length.',
                );
            }
            return opened;
        },
    });

    const deleteAllExternalMemory = async (): Promise<void> => {
        const failures: unknown[] = [];
        for (const object of objects.values()) {
            try {
                await deleteObjectRecords(object);
            } catch (error) {
                failures.push(error);
            } finally {
                destroyExternalMemoryObjectInMemory(object);
            }
        }
        objects.clear();
        externalMemoryByteLength = 0n;
        externalMemoryRecordCount = 0;
        if (failures.length !== 0) {
            throw new BrowserActionStorageCustodyError(
                'StorageFailure',
                'Common-proof external-memory cleanup failed.',
                failures,
            );
        }
    };

    async function cleanupDurableProofRecords(): Promise<void> {
        if (durableProofRecordsDeleted) {
            return;
        }
        try {
            await input.capacityReservation.deleteAuthenticatedLogicalRecords(
                attemptLogicalRecordPrefix,
            );
        } catch (error) {
            throw new BrowserActionStorageCustodyError(
                'StorageFailure',
                'Common-proof authenticated durable-record cleanup failed.',
                error,
            );
        }
        durableProofRecordsDeleted = true;
        for (const object of objects.values()) {
            destroyExternalMemoryObjectInMemory(object);
        }
        objects.clear();
        externalMemoryByteLength = 0n;
        externalMemoryRecordCount = 0;
        outputChunks.clear();
        outputByteLength = 0;
        outputSealed = false;
        outputTerminalChunkIndex = undefined;
    }

    async function evictTerminalCheckpoint(): Promise<void> {
        if (checkpointEvictionCompleted) {
            return;
        }
        preserveCheckpointLineageForTerminalCleanup();
        if (checkpointEvictionCompleted) {
            return;
        }
        const checkpointLineageIdentifier = terminalCheckpointLineageIdentifier;
        if (
            checkpointLineageIdentifier === undefined ||
            input.checkpoint === undefined
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'Common-proof terminal checkpoint cleanup lost its retained lineage identifier.',
            );
        }
        await input.checkpoint.store.evict(checkpointLineageIdentifier);
        if (terminalCheckpointOperationIdentity !== undefined) {
            await input.checkpoint.store.releaseOperationIdentity(
                terminalCheckpointOperationIdentity,
            );
            terminalCheckpointOperationIdentity = undefined;
        }
        checkpointEvictionCompleted = true;
        checkpointLineageIdentifier.fill(0);
        terminalCheckpointLineageIdentifier = undefined;
    }

    async function releaseTerminalCapacityReservation(): Promise<void> {
        if (capacityReservationReleased) {
            return;
        }
        await input.capacityReservation.release();
        capacityReservationReleased = true;
    }

    async function cleanupTerminalProofAuthority(): Promise<unknown[]> {
        preserveCheckpointLineageForTerminalCleanup();
        const failures: unknown[] = [];
        try {
            await cleanupDurableProofRecords();
        } catch (error) {
            failures.push(error);
        }
        try {
            await evictTerminalCheckpoint();
        } catch (error) {
            failures.push(error);
        }
        if (durableProofRecordsDeleted) {
            try {
                await releaseTerminalCapacityReservation();
            } catch (error) {
                failures.push(error);
            }
        }
        retirementCleanupCompleted =
            durableProofRecordsDeleted &&
            checkpointEvictionCompleted &&
            capacityReservationReleased;
        return failures;
    }

    const armApplicationHandoff =
        async (): Promise<CommonProofApplicationHandoff> => {
            assertOpen();
            if (
                applicationHandoffArmed ||
                !outputSealed ||
                outputByteLength === 0 ||
                objects.size !== 0 ||
                externalMemoryByteLength !== 0n ||
                externalMemoryRecordCount !== 0
            ) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidState',
                    'Common-proof application handoff requires one sealed output with released scratch authority.',
                );
            }
            const markerPayload = hexToExactBytes(
                attemptLogicalRecordPrefix.slice(
                    'common-proof-attempt/'.length,
                    -1,
                ),
                foundationHashByteLength,
                'Common-proof application handoff attempt identifier',
            );
            const canonicalMarkerRecordBytes = encodePublicRecord(
                applicationHandoffLogicalRecordKey,
                markerPayload,
            );
            const transaction = await input.store.beginTransaction({
                lifetimeMilliseconds: limits.transactionLifetimeMilliseconds,
            });
            let committedRecord: Uint8Array | undefined;
            try {
                const lease = await transaction.issueWriteLease({
                    declaredByteLength: canonicalMarkerRecordBytes.byteLength,
                    expectedCurrentValue: null,
                    logicalRecordKey: applicationHandoffLogicalRecordKey,
                });
                await lease.write(canonicalMarkerRecordBytes);
                await lease.seal(({ bytes }) => {
                    const opened = decodePublicRecord(
                        applicationHandoffLogicalRecordKey,
                        bytes,
                    );
                    try {
                        if (!bytesEqual(opened, markerPayload)) {
                            throw new BrowserActionStorageCustodyError(
                                'RecordAuthenticationFailed',
                                'The staged common-proof handoff marker changed before commit.',
                            );
                        }
                    } finally {
                        opened.fill(0);
                    }
                });
                await transaction.commit();
                committedRecord = await input.store.readAuthenticated({
                    authenticate: ({ bytes }) => {
                        const opened = decodePublicRecord(
                            applicationHandoffLogicalRecordKey,
                            bytes,
                        );
                        try {
                            if (!bytesEqual(opened, markerPayload)) {
                                throw new BrowserActionStorageCustodyError(
                                    'RecordAuthenticationFailed',
                                    'The committed common-proof handoff marker changed during readback.',
                                );
                            }
                        } finally {
                            opened.fill(0);
                        }
                    },
                    logicalRecordKey: applicationHandoffLogicalRecordKey,
                });
                if (
                    committedRecord === undefined ||
                    !bytesEqual(committedRecord, canonicalMarkerRecordBytes)
                ) {
                    throw new BrowserActionStorageCustodyError(
                        'RecordAuthenticationFailed',
                        'The committed common-proof handoff marker is unavailable or differs from its exact bytes.',
                    );
                }
                applicationHandoffArmed = true;
                return Object.freeze({
                    canonicalMarkerRecordBytes:
                        canonicalMarkerRecordBytes.slice(),
                    logicalRecordKey: applicationHandoffLogicalRecordKey,
                });
            } catch (error) {
                return await closeTransactionAfterFailure(transaction, error);
            } finally {
                markerPayload.fill(0);
                canonicalMarkerRecordBytes.fill(0);
                committedRecord?.fill(0);
            }
        };

    return Object.freeze({
        armApplicationHandoff,
        ...(configuredCheckpointCustody === undefined
            ? {}
            : { checkpointCustody: configuredCheckpointCustody }),
        completeVerifiedOutput: async () => {
            assertOpen();
            if (
                !outputSealed ||
                outputByteLength === 0 ||
                objects.size !== 0 ||
                externalMemoryByteLength !== 0n ||
                externalMemoryRecordCount !== 0
            ) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidState',
                    'Common-proof output completion requires one sealed output and no retained scratch state.',
                );
            }
            state = 'retiring';
            const completionFailures = await cleanupTerminalProofAuthority();
            permanentlyRetireInMemory();
            if (completionFailures.length !== 0) {
                throw new BrowserActionStorageCustodyError(
                    'StorageFailure',
                    'Verified common-proof output completion could not release every temporary authority.',
                    completionFailures,
                );
            }
        },
        copyCheckpointResumeDescriptor: () =>
            latestCheckpointResumeDescriptor === undefined
                ? undefined
                : copyCheckpointResumeDescriptor(
                      latestCheckpointResumeDescriptor,
                  ),
        authenticatedOutput: (): AuthenticatedCommonProofInputStore => {
            assertOpen();
            if (!outputSealed || outputByteLength === 0) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidState',
                    'Common-proof canonical output is not sealed.',
                );
            }
            return Object.freeze({
                declaredByteLength: outputByteLength,
                readCommittedChunk: (chunkIndex, exactByteLength) =>
                    outputStore.readChunk(chunkIndex, exactByteLength),
            });
        },
        externalMemory: Object.freeze({
            executeTransaction: (request: CommonProofExternalMemoryRequest) =>
                executeTransaction(request, false),
        }),
        outputStore,
        prefixReplayExternalMemory: Object.freeze({
            executeDeterministicPrefixReplayTransaction: (
                request: CommonProofExternalMemoryRequest,
            ) => executeTransaction(request, true),
        }),
        releaseExternalMemory: async () => {
            assertOpen();
            state = 'releasing-external-memory';
            try {
                await deleteAllExternalMemory();
                state = 'open';
            } catch (error) {
                permanentlyRetireInMemory();
                throw error;
            }
        },
        retire: async () => {
            if (retirementCleanupCompleted) {
                return;
            }
            state = 'retiring';
            const cleanupFailures = await cleanupTerminalProofAuthority();
            permanentlyRetireInMemory();
            if (cleanupFailures.length !== 0) {
                throw new BrowserActionStorageCustodyError(
                    'StorageFailure',
                    'Common-proof browser custody retirement could not remove every record.',
                    cleanupFailures,
                );
            }
        },
        sealCanonicalOutput: () => {
            assertOpen();
            if (outputSealed || outputChunks.size === 0) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidState',
                    'Common-proof canonical output cannot be sealed in its current state.',
                );
            }
            outputSealed = true;
        },
        suspendForAuthenticatedResume: async () => {
            assertOpen();
            if (latestCheckpointResumeDescriptor === undefined) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidState',
                    'Common-proof custody cannot suspend without an authenticated checkpoint.',
                );
            }
            if (checkpointOperationIdentity !== undefined) {
                if (input.checkpoint === undefined) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidState',
                        'Common-proof checkpoint identity cleanup lost its authenticated store.',
                    );
                }
                await input.checkpoint.store.releaseOperationIdentity(
                    checkpointOperationIdentity,
                );
                checkpointOperationIdentity = undefined;
            }
            await releaseTerminalCapacityReservation();
            for (const object of objects.values()) {
                destroyExternalMemoryObjectInMemory(object);
            }
            objects.clear();
            externalMemoryByteLength = 0n;
            externalMemoryRecordCount = 0;
            outputChunks.clear();
            outputByteLength = 0;
            outputSealed = false;
            outputTerminalChunkIndex = undefined;
            permanentlyRetireInMemory(false);
            retirementCleanupCompleted = true;
        },
    });
};
