import { shake256 } from '@noble/hashes/sha3.js';
import {
    BrowserActionStorageCustodyError,
    deriveFoundationRosterParameters,
    isProtocolHash,
    type BrowserActionRandomnessRecordContext,
    type BrowserActionStorageRootBinding,
    type BrowserFoundationWitnessProvisioningBinding,
    type BrowserLocalRecordExpectedContext,
    type BrowserLocalRecordIdentifierInput,
    type UntrustedExpectedStorageRootCommitment,
    type WorkerBrowserFoundationInitializationPreparationInput,
} from '@sealed-lattice/types';

import { maximumClosedWorkerCommandByteLength } from '../action-randomness-command-byte-limits.js';

import type { ClosedWorkerCommonProofScratchRecordIdentifierInput } from './authorities.js';
export const actionStorageRootByteLength = 48;
export const actionRandomnessRootByteLength = 64;
export const attemptIdentifierByteLength = 32;
export const capabilityByteLength = 32;
export const deviceWrappingNonceByteLength = 12;
export const deviceWrappingTagByteLength = 16;
export const foundationHashByteLength = 64;
export const handleByteLength = 4;
export const localRecordNonceByteLength = 12;
export const maximumLocalRecordPlaintextByteLength = 1_048_576;
export const maximumCommandByteLength = maximumClosedWorkerCommandByteLength;
export const maximumWrappedStorageRootByteLength = 492;
export const mlDsa65VerificationKeyByteLength = 1_952;
export const mlDsa65SignatureByteLength = 3_309;
export const mlKem768CiphertextByteLength = 1_088;
export const mlKem768EncapsulationKeyByteLength = 1_184;
export const mlKem768SharedSecretByteLength = 32;
export const wasm32WordByteLength = 4;
const opaqueWorkerIdentifierPattern = /^[0-9a-f]{64}$/u;
export const storageNamespacePattern = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
export const repairTextEncoder = new TextEncoder();
export const setupMailboxSignatureContext = new TextEncoder().encode(
    'sealed-lattice/mailbox-signature/v1',
);
export const objectSignatureContext = new TextEncoder().encode(
    'sealed-lattice/object-signature/v1',
);
const foundationWitnessAuthorizedEmptyRecordDomain = new TextEncoder().encode(
    'sealed-lattice/runtime/foundation-state-witness-authorized-empty/v1',
);
export const foundationWitnessStateKeyDomain = new TextEncoder().encode(
    'sealed-lattice/runtime/foundation-state-witness-state-key/v1',
);
const foundationWitnessRecordVersion = 1;

export const protocolHashBytes = (
    value: unknown,
    label: string,
): Uint8Array<ArrayBuffer> => {
    if (!isProtocolHash(value)) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            `${label} must be a lowercase 64-byte hexadecimal hash.`,
        );
    }
    const bytes = new Uint8Array(foundationHashByteLength);
    for (let byteIndex = 0; byteIndex < bytes.byteLength; byteIndex += 1) {
        bytes[byteIndex] = Number.parseInt(
            value.slice(byteIndex * 2, byteIndex * 2 + 2),
            16,
        );
    }
    return bytes;
};

export const requireOpaqueWorkerIdentifier = (
    value: unknown,
    label: string,
): string => {
    if (
        typeof value !== 'string' ||
        !opaqueWorkerIdentifierPattern.test(value)
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            `${label} is malformed.`,
        );
    }

    return value;
};

export const copyBoundedBytes = (
    value: unknown,
    label: string,
): Uint8Array<ArrayBuffer> => {
    if (
        !(value instanceof Uint8Array) ||
        value.byteLength === 0 ||
        value.byteLength > maximumCommandByteLength
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            `${label} has an unsupported length.`,
        );
    }

    return value.slice();
};

export const copyExactBytes = (
    value: unknown,
    expectedByteLength: number,
    label: string,
): Uint8Array<ArrayBuffer> => {
    if (
        !(value instanceof Uint8Array) ||
        value.byteLength !== expectedByteLength
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            `${label} must contain exactly ${expectedByteLength} bytes.`,
        );
    }
    const copy = new Uint8Array(expectedByteLength);
    copy.set(value);

    return copy;
};

export const concatenateBytes = (
    ...values: readonly Uint8Array[]
): Uint8Array<ArrayBuffer> => {
    const byteLength = values.reduce(
        (accumulatedByteLength, value) =>
            accumulatedByteLength + value.byteLength,
        0,
    );
    if (
        !Number.isSafeInteger(byteLength) ||
        byteLength > maximumCommandByteLength
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The local storage-root command exceeds its supported byte limit.',
        );
    }
    const output = new Uint8Array(byteLength);
    let offset = 0;
    for (const value of values) {
        output.set(value, offset);
        offset += value.byteLength;
    }

    return output;
};

export const encodeUnsigned32 = (value: number): Uint8Array<ArrayBuffer> => {
    if (!Number.isSafeInteger(value) || value <= 0 || value > 0xffff_ffff) {
        throw new BrowserActionStorageCustodyError(
            'InvalidState',
            'The WASM local storage-root handle is invalid.',
        );
    }
    const bytes = new Uint8Array(handleByteLength);
    new DataView(bytes.buffer).setUint32(0, value, true);

    return bytes;
};

export const encodeCanonicalUnsigned16 = (
    value: number,
    label: string,
): Uint8Array<ArrayBuffer> => {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            `${label} must be an unsigned 16-bit integer.`,
        );
    }
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(0, value, true);

    return bytes;
};

export const encodeCanonicalUnsigned32 = (
    value: number,
    label: string,
): Uint8Array<ArrayBuffer> => {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            `${label} must be an unsigned 32-bit integer.`,
        );
    }
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);

    return bytes;
};

const encodeCanonicalUnsigned64 = (
    value: bigint,
    label: string,
): Uint8Array<ArrayBuffer> => {
    if (
        typeof value !== 'bigint' ||
        value < 0n ||
        value > 0xffff_ffff_ffff_ffffn
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            `${label} must be an unsigned 64-bit integer.`,
        );
    }
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, value, true);

    return bytes;
};

type CopiedBrowserFoundationInitializationInput = Readonly<{
    actionRandomnessRecordContext: BrowserActionRandomnessRecordContext;
    orderedWitnessBindings: readonly BrowserFoundationWitnessProvisioningBinding[];
    runtimeBuildManifestHash: Uint8Array<ArrayBuffer>;
}>;

export const destroyBrowserFoundationInitializationInput = (
    input: CopiedBrowserFoundationInitializationInput,
): void => {
    input.runtimeBuildManifestHash.fill(0);
    for (const binding of input.orderedWitnessBindings) {
        binding.subjectParticipantIdentity.fill(0);
        binding.witnessParticipantIdentity.fill(0);
    }
};

export const copyBrowserFoundationInitializationInput = (
    input: WorkerBrowserFoundationInitializationPreparationInput,
): CopiedBrowserFoundationInitializationInput => {
    const untrustedOrderedWitnessBindings: unknown =
        input?.orderedWitnessBindings;
    if (
        typeof input !== 'object' ||
        input === null ||
        !Array.isArray(untrustedOrderedWitnessBindings)
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'Browser foundation initialization requires ordered witness bindings.',
        );
    }
    try {
        deriveFoundationRosterParameters(
            untrustedOrderedWitnessBindings.length + 1,
        );
    } catch (error) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'Browser foundation initialization witness bindings are outside the configurable participant-count range.',
            error,
        );
    }
    if (
        typeof input.actionRandomnessRecordContext !== 'object' ||
        input.actionRandomnessRecordContext === null ||
        input.actionRandomnessRecordContext.recordVersion !== 0n ||
        input.actionRandomnessRecordContext.predecessorRecordHash !== undefined
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'Fresh browser foundation initialization requires action-randomness record version zero without a predecessor.',
        );
    }
    const runtimeBuildManifestHash = copyExactBytes(
        input.runtimeBuildManifestHash,
        foundationHashByteLength,
        'Runtime build-manifest hash',
    );
    const orderedWitnessBindings = untrustedOrderedWitnessBindings.map(
        (binding: unknown, bindingIndex) => {
            if (typeof binding !== 'object' || binding === null) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    `Foundation witness provisioning binding ${String(bindingIndex)} must be an object.`,
                );
            }
            const bindingRecord = binding as Record<string, unknown>;
            return Object.freeze({
                subjectParticipantIdentity: copyExactBytes(
                    bindingRecord.subjectParticipantIdentity,
                    foundationHashByteLength,
                    `Witness provisioning subject participant identity ${String(bindingIndex)}`,
                ),
                witnessParticipantIdentity: copyExactBytes(
                    bindingRecord.witnessParticipantIdentity,
                    foundationHashByteLength,
                    `Witness provisioning witness participant identity ${String(bindingIndex)}`,
                ),
            });
        },
    );
    return Object.freeze({
        actionRandomnessRecordContext: Object.freeze({ recordVersion: 0n }),
        orderedWitnessBindings: Object.freeze(orderedWitnessBindings),
        runtimeBuildManifestHash,
    });
};

export const encodeFoundationWitnessRole = (input: {
    binding: BrowserActionStorageRootBinding;
    roleIndex: number;
    runtimeBuildManifestHash: Uint8Array;
    witnessBinding: BrowserFoundationWitnessProvisioningBinding;
}): Uint8Array<ArrayBuffer> =>
    concatenateBytes(
        encodeCanonicalUnsigned16(
            foundationWitnessRecordVersion,
            'Witness state record version',
        ),
        encodeBinding(input.binding),
        input.runtimeBuildManifestHash,
        encodeCanonicalUnsigned16(input.roleIndex, 'Witness state role index'),
        input.witnessBinding.subjectParticipantIdentity,
        input.witnessBinding.witnessParticipantIdentity,
    );

export const domainSeparatedHash = (
    domain: Uint8Array,
    canonicalInput: Uint8Array,
    label: string,
): Uint8Array<ArrayBuffer> => {
    const hash = shake256.create({ dkLen: foundationHashByteLength });
    hash.update(
        encodeCanonicalUnsigned32(domain.byteLength, `${label} domain length`),
    );
    hash.update(domain);
    hash.update(
        encodeCanonicalUnsigned32(
            canonicalInput.byteLength,
            `${label} input length`,
        ),
    );
    hash.update(canonicalInput);

    return hash.digest();
};

export const encodeFoundationWitnessAuthorizedEmpty = (
    canonicalRole: Uint8Array,
): Uint8Array<ArrayBuffer> =>
    concatenateBytes(
        encodeCanonicalUnsigned32(
            foundationWitnessAuthorizedEmptyRecordDomain.byteLength,
            'Witness authorized-empty domain length',
        ),
        foundationWitnessAuthorizedEmptyRecordDomain,
        encodeCanonicalUnsigned32(
            canonicalRole.byteLength,
            'Witness authorized-empty role length',
        ),
        canonicalRole,
    );

const encodeByteLength = (
    byteLength: number,
    label: string,
): Uint8Array<ArrayBuffer> => encodeCanonicalUnsigned32(byteLength, label);

type EncodedLocalRecordIdentifierInput = Readonly<{
    context: Uint8Array<ArrayBuffer>;
    recordTypeCode: number;
}>;

export const encodeLocalRecordIdentifierInput = (
    input:
        | BrowserLocalRecordIdentifierInput
        | ClosedWorkerCommonProofScratchRecordIdentifierInput,
): EncodedLocalRecordIdentifierInput => {
    if (typeof input !== 'object' || input === null) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The local-record identifier input must be an object.',
        );
    }
    switch (input.recordType) {
        case 'actionRandomness':
            return { context: new Uint8Array(0), recordTypeCode: 1 };
        case 'publicCoinPrivateMaterial':
            return { context: new Uint8Array(0), recordTypeCode: 2 };
        case 'sourceVssMaterial':
            return {
                context: copyExactBytes(
                    input.materialContextHash,
                    foundationHashByteLength,
                    'Material-context hash',
                ),
                recordTypeCode: 3,
            };
        case 'aggregateThresholdShare':
            return {
                context: copyExactBytes(
                    input.recipientInputRoot,
                    foundationHashByteLength,
                    'Recipient-input root',
                ),
                recordTypeCode: 4,
            };
        case 'proofAttempt':
            return {
                context: copyExactBytes(
                    input.applicationSlotHash,
                    foundationHashByteLength,
                    'Application-slot hash',
                ),
                recordTypeCode: 5,
            };
        case 'ballotAttempt': {
            if (
                !(input.canonicalBallotStatementBytes instanceof Uint8Array) ||
                input.canonicalBallotStatementBytes.byteLength === 0 ||
                input.canonicalBallotStatementBytes.byteLength >
                    maximumCommandByteLength
            ) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'The canonical ballot statement has an unsupported length.',
                );
            }
            const statement = input.canonicalBallotStatementBytes.slice();
            const attemptIdentifier = copyExactBytes(
                input.ballotEncryptionAttemptIdentifier,
                32,
                'Ballot-encryption attempt identifier',
            );

            return {
                context: concatenateBytes(
                    encodeByteLength(
                        statement.byteLength,
                        'Ballot-statement byte length',
                    ),
                    statement,
                    attemptIdentifier,
                ),
                recordTypeCode: 6,
            };
        }
        case 'exactOutputChunk':
            return {
                context: concatenateBytes(
                    encodeCanonicalUnsigned16(
                        input.capabilityKind,
                        'Capability kind',
                    ),
                    copyExactBytes(
                        input.exactOutputHash,
                        foundationHashByteLength,
                        'Exact-output hash',
                    ),
                    encodeCanonicalUnsigned64(
                        input.outputChunkIndex,
                        'Output-chunk index',
                    ),
                ),
                recordTypeCode: 7,
            };
        case 'subjectState':
            return {
                context: copyExactBytes(
                    input.stateKey,
                    foundationHashByteLength,
                    'Subject-state key',
                ),
                recordTypeCode: 8,
            };
        case 'witnessState':
            return {
                context: copyExactBytes(
                    input.stateKey,
                    foundationHashByteLength,
                    'Witness-state key',
                ),
                recordTypeCode: 9,
            };
        case 'checkpointManifest': {
            const orderedSourceDigests: unknown = input.orderedSourceDigests;
            if (!Array.isArray(orderedSourceDigests)) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'Ordered checkpoint source digests must be an array.',
                );
            }
            if (orderedSourceDigests.length > 4_096) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'Ordered checkpoint source digests exceed the supported count.',
                );
            }
            const sourceDigests = orderedSourceDigests.map((digest) => {
                if (!(digest instanceof Uint8Array)) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidInput',
                        'Each ordered checkpoint source digest must be bytes.',
                    );
                }

                return copyExactBytes(
                    digest,
                    foundationHashByteLength,
                    'Checkpoint source digest',
                );
            });

            return {
                context: concatenateBytes(
                    copyExactBytes(
                        input.runtimeBuildManifestHash,
                        foundationHashByteLength,
                        'Runtime build-manifest hash',
                    ),
                    copyExactBytes(
                        input.checkpointLineageIdentifier,
                        32,
                        'Checkpoint-lineage identifier',
                    ),
                    encodeCanonicalUnsigned16(
                        input.operationKind,
                        'Checkpoint operation kind',
                    ),
                    encodeCanonicalUnsigned32(
                        input.safeBoundaryOrdinal,
                        'Checkpoint safe-boundary ordinal',
                    ),
                    encodeCanonicalUnsigned32(
                        sourceDigests.length,
                        'Checkpoint source-digest count',
                    ),
                    ...sourceDigests,
                ),
                recordTypeCode: 10,
            };
        }
        case 'checkpointChunk':
            return {
                context: concatenateBytes(
                    copyExactBytes(
                        input.checkpointIdentifier,
                        foundationHashByteLength,
                        'Checkpoint identifier',
                    ),
                    encodeCanonicalUnsigned32(
                        input.chunkIndex,
                        'Checkpoint chunk index',
                    ),
                    copyExactBytes(
                        input.chunkDigest,
                        foundationHashByteLength,
                        'Checkpoint chunk digest',
                    ),
                ),
                recordTypeCode: 11,
            };
        case 'commonProofExternalMemory': {
            const externalMemoryRecordKindCode =
                input.externalMemoryRecordKind === 'object-header'
                    ? 1
                    : input.externalMemoryRecordKind === 'data-chunk'
                      ? 2
                      : input.externalMemoryRecordKind === 'seal-marker'
                        ? 3
                        : 0;
            if (externalMemoryRecordKindCode === 0) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'Common-proof external-memory record kind is unsupported.',
                );
            }
            return {
                context: concatenateBytes(
                    copyExactBytes(
                        input.commonProofEnvironmentIdentifier,
                        32,
                        'Common-proof environment identifier',
                    ),
                    copyExactBytes(
                        input.commonProofRuntimeBindingHash,
                        foundationHashByteLength,
                        'Common-proof runtime-binding hash',
                    ),
                    copyExactBytes(
                        input.proofAttemptLineageIdentifier,
                        32,
                        'Proof-attempt lineage identifier',
                    ),
                    encodeCanonicalUnsigned16(
                        externalMemoryRecordKindCode,
                        'Common-proof external-memory record kind',
                    ),
                    encodeCanonicalUnsigned32(
                        input.externalMemoryObjectOrdinal,
                        'Common-proof external-memory object ordinal',
                    ),
                    encodeCanonicalUnsigned32(
                        input.externalMemoryChunkOrdinal,
                        'Common-proof external-memory chunk ordinal',
                    ),
                    encodeCanonicalUnsigned64(
                        input.externalMemoryByteOffset,
                        'Common-proof external-memory byte offset',
                    ),
                ),
                recordTypeCode: 12,
            };
        }
    }
};

export const encodeLocalRecordExpectedContext = (
    input:
        | BrowserLocalRecordExpectedContext
        | Readonly<{
              actionRandomnessCommitment: Uint8Array;
              identifierInput: ClosedWorkerCommonProofScratchRecordIdentifierInput;
              predecessorRecordHash?: Uint8Array;
              recordVersion: bigint;
          }>,
): Uint8Array<ArrayBuffer> => {
    if (typeof input !== 'object' || input === null) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The local-record expected context must be an object.',
        );
    }
    const encodedIdentifier = encodeLocalRecordIdentifierInput(
        input.identifierInput,
    );
    const predecessorRecordHash =
        input.predecessorRecordHash === undefined
            ? undefined
            : copyExactBytes(
                  input.predecessorRecordHash,
                  foundationHashByteLength,
                  'Predecessor record hash',
              );
    if (
        (input.recordVersion === 0n) !==
        (predecessorRecordHash === undefined)
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'Predecessor record-hash presence must match the local-record version.',
        );
    }

    return concatenateBytes(
        copyExactBytes(
            input.actionRandomnessCommitment,
            foundationHashByteLength,
            'Action-randomness commitment',
        ),
        encodeCanonicalUnsigned16(
            encodedIdentifier.recordTypeCode,
            'Local-record type',
        ),
        encodeByteLength(
            encodedIdentifier.context.byteLength,
            'Record-identifier context length',
        ),
        encodedIdentifier.context,
        encodeCanonicalUnsigned64(input.recordVersion, 'Local-record version'),
        predecessorRecordHash === undefined
            ? new Uint8Array([0])
            : concatenateBytes(new Uint8Array([1]), predecessorRecordHash),
    );
};

export const decodeUnsigned32 = (bytes: Uint8Array, offset: number): number => {
    if (offset < 0 || offset + wasm32WordByteLength > bytes.byteLength) {
        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The WASM local storage-root output is truncated.',
        );
    }

    return new DataView(
        bytes.buffer,
        bytes.byteOffset + offset,
        wasm32WordByteLength,
    ).getUint32(0, true);
};

export const arrayBufferFromBytes = (bytes: Uint8Array): ArrayBuffer => {
    const copy = new Uint8Array(bytes.byteLength);
    copy.set(bytes);

    return copy.buffer;
};

export const encodeBinding = (
    binding: BrowserActionStorageRootBinding,
): Uint8Array<ArrayBuffer> =>
    concatenateBytes(
        copyExactBytes(binding.suiteId, foundationHashByteLength, 'Suite ID'),
        copyExactBytes(
            binding.ceremonyContextHash,
            foundationHashByteLength,
            'Ceremony-context hash',
        ),
        copyExactBytes(
            binding.actionContextHash,
            foundationHashByteLength,
            'Action-context hash',
        ),
        copyExactBytes(
            binding.participantId,
            foundationHashByteLength,
            'Participant identity',
        ),
    );

export const copyBinding = (
    binding: BrowserActionStorageRootBinding,
): BrowserActionStorageRootBinding =>
    Object.freeze({
        actionContextHash: copyExactBytes(
            binding.actionContextHash,
            foundationHashByteLength,
            'Action-context hash',
        ),
        ceremonyContextHash: copyExactBytes(
            binding.ceremonyContextHash,
            foundationHashByteLength,
            'Ceremony-context hash',
        ),
        participantId: copyExactBytes(
            binding.participantId,
            foundationHashByteLength,
            'Participant identity',
        ),
        suiteId: copyExactBytes(
            binding.suiteId,
            foundationHashByteLength,
            'Suite ID',
        ),
    });

export const encodeActionRandomnessRecordContext = (
    binding: BrowserActionStorageRootBinding,
    input: BrowserActionRandomnessRecordContext,
): Uint8Array<ArrayBuffer> => {
    if (typeof input !== 'object' || input === null) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The action-randomness record context must be an object.',
        );
    }
    const predecessorRecordHash =
        input.predecessorRecordHash === undefined
            ? undefined
            : copyExactBytes(
                  input.predecessorRecordHash,
                  foundationHashByteLength,
                  'Action-randomness predecessor record hash',
              );
    if (
        (input.recordVersion === 0n) !==
        (predecessorRecordHash === undefined)
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'Action-randomness predecessor presence must match the record version.',
        );
    }
    return concatenateBytes(
        encodeBinding(binding),
        encodeCanonicalUnsigned64(
            input.recordVersion,
            'Action-randomness record version',
        ),
        predecessorRecordHash === undefined
            ? new Uint8Array([0])
            : concatenateBytes(new Uint8Array([1]), predecessorRecordHash),
    );
};

export const untrustedExpectedCommitmentBytes = (
    value: UntrustedExpectedStorageRootCommitment,
): Uint8Array<ArrayBuffer> =>
    copyExactBytes(
        value.storageRootCommitment,
        foundationHashByteLength,
        'Untrusted expected storage-root commitment',
    );
