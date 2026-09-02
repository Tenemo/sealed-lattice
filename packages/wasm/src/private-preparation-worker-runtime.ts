/// <reference lib="webworker" />

import {
    actionSignatureSigningRandomnessByteLength,
    actionSignatureSecretKeyByteLength,
    openActionSignatureRuntime,
    type ActionSignatureRuntime,
} from './action-signature-runtime.js';
import {
    finalityTargetBodyByteLength,
    openFinalityRuntime,
    type FinalitySignatureCarrier,
    type SourceCarrier,
} from './finality-runtime.js';
import {
    instantiateConstructionKernelCommandRuntime,
    type ConstructionKernelCommandRuntime,
    type FoundationKernelLoaderOptions,
    type KernelResourceMeasurement,
} from './foundation-kernel/kernel-runtime.js';
import {
    pairDecryptionKeyByteLength,
    pairEncryptionRandomnessByteLength,
} from './pair-encryption-runtime.js';
import {
    openPreparationMaterialRuntime,
    preparationContributionOpeningVectorByteLength,
    preparationPairwiseMasterVectorByteLength,
    preparationPlaintextByteLength,
    type PreparationMaterialRuntime,
} from './preparation-material-runtime.js';
import {
    actionSignatureCarrierByteLength,
    openPreparationParentRuntime,
    preparationParentBodyByteLength,
    type PreparationParentRuntime,
} from './preparation-parent-runtime.js';
import {
    openPrivatePreparationBodyRuntime,
    privatePreparationBodyByteLength,
    type PrivatePreparationBodyRuntime,
    type PrivatePreparationContextInput,
} from './private-preparation-body-runtime.js';
import {
    createProtectedRecord,
    DurableStateError,
    generateBrowserLocalRootKey,
    openProtectedRecord,
    PrivatePreparationDurableState,
    type ProtectedRecord,
} from './private-preparation-durable-state.js';
import type {
    PrivatePreparationActionContext,
    PrivatePreparationWorkerFailure,
    PrivatePreparationWorkerInitialization,
    PrivatePreparationWorkerRequest,
    PrivatePreparationWorkerResponse,
    PrivatePreparationConsumption,
    PublishedFinalityPackage,
    PublishedPreparationPackage,
    PublishedSourcePackage,
    SourcePublicationChoice,
    TallyEvaluationProgress,
} from './private-preparation-worker-protocol.js';
import {
    completionRosterByteLength,
    openRosterRuntime,
    type RosterRuntime,
} from './roster-runtime.js';
import {
    abstentionSourceBodyByteLength,
    heldSubsetKeyVectorByteLength,
    sourceScoreEncodingCount,
    openSourceRuntime,
    submittedSourceBodyByteLength,
    type PreparationParentCarrier,
    type SourceDeclaration,
    type SourceRuntime,
    type VerifiedCompletePreparation,
} from './source-runtime.js';

const completionProfileParticipantCount = 10;
const signaturePurposeCount = 4;
const identityByteLength = 64;
const localContextDomainByteLength = 32;
const localContextDomain = 'sealed-lattice/local-record/v3';
const localContextByteLength =
    localContextDomainByteLength + 6 * identityByteLength + 2 + 2 + 8 + 2 + 8;
const noPeerPosition = 0xffff;
const actionStateKind = 1;
const preparationStateKind = 2;
const privatePreparationSlotStateKind = 3;
const sourceStateKind = 4;
const finalityStateKind = 5;
// Object kinds 6 and 7 are reserved for rejected tally-activation records.
const noResultStateKind = 8;
const rosterBoundActionPhase = 1;
const unsignedPreparationPhase = 1;
const publishedPreparationPhase = 2;
const consumedPrivatePreparationPhase = 1;
const resolvedPrivatePreparationPhase = 2;
const burnedPrivatePreparationPhase = 3;
const unsignedSourcePhase = 1;
const publishedSourcePhase = 2;
const unsignedFinalityPhase = 1;
const publishedFinalityPhase = 2;
const privatePreparationOperationOrdinal = 1n;
const sourceOperationOrdinal = 0n;

type WorkerConfiguration = Readonly<{
    runtimeIdentity: Uint8Array;
    candidateBuildIdentity: Uint8Array;
    afterDurableConsume?: () => Promise<void> | void;
    afterDurableSourceBind?: () => Promise<void> | void;
}>;

type LocalRecordContext = Readonly<{
    runtimeIdentity: Uint8Array;
    candidateBuildIdentity: Uint8Array;
    actionProposalIdentity: Uint8Array;
    actionDefinitionIdentity: Uint8Array;
    rosterIdentity: Uint8Array;
    predecessorIdentity: Uint8Array;
    participantPosition: number;
    objectKind: number;
    generation: bigint;
    peerPosition: number;
    operationOrdinal: bigint;
}>;

type ActionState = {
    phase: typeof rosterBoundActionPhase;
    generation: bigint;
    runtimeIdentity: Uint8Array;
    candidateBuildIdentity: Uint8Array;
    actionProposalIdentity: Uint8Array;
    actionDefinitionIdentity: Uint8Array;
    rosterIdentity: Uint8Array;
    predecessorIdentity: Uint8Array;
    participantPosition: number;
    canonicalRosterBytes: Uint8Array;
    signatureBodyIdentities: Uint8Array[];
    signingSecretKey: Uint8Array;
    mailboxDecapsulationKey: Uint8Array;
};

type LoadedActionState = Readonly<{
    record: ProtectedRecord;
    rootKey: CryptoKey;
    state: ActionState;
}>;

type PreparationState = {
    phase: typeof publishedPreparationPhase | typeof unsignedPreparationPhase;
    generation: bigint;
    preparationAttempt: number;
    parentIdentity: Uint8Array;
    parentBody: Uint8Array;
    parentSignature: Uint8Array;
    privateBodyIdentities: Uint8Array[];
    privateBodies: Uint8Array[];
    contributionOpenings: Uint8Array;
    pairwiseMasters: Uint8Array;
};

type LoadedPreparationState = Readonly<{
    record: ProtectedRecord;
    state: PreparationState;
}>;

type PrivatePreparationSlotState = {
    phase:
        | typeof burnedPrivatePreparationPhase
        | typeof consumedPrivatePreparationPhase
        | typeof resolvedPrivatePreparationPhase;
    generation: bigint;
    preparationAttempt: number;
    senderPosition: number;
    parentIdentity: Uint8Array;
    bodyIdentity: Uint8Array;
    verifiedPlaintextIdentity: Uint8Array;
    plaintext: Uint8Array;
};

type LoadedPrivatePreparationSlotState = Readonly<{
    record: ProtectedRecord;
    state: PrivatePreparationSlotState;
}>;

type SourceState = {
    phase: typeof publishedSourcePhase | typeof unsignedSourcePhase;
    generation: bigint;
    preparationAttempt: number;
    verifiedPreparationRoot: Uint8Array;
    declaration: SourceDeclaration;
    scoreEncodings: Uint8Array;
    sourceBody: Uint8Array;
    sourceBodyIdentity: Uint8Array;
    sourceSignature: Uint8Array;
    heldSubsetKeys: Uint8Array;
};

type LoadedSourceState = Readonly<{
    record: ProtectedRecord;
    state: SourceState;
}>;

type FinalityState = {
    phase: typeof publishedFinalityPhase | typeof unsignedFinalityPhase;
    generation: bigint;
    preparationAttempt: number;
    verifiedPreparationRoot: Uint8Array;
    targetBody: Uint8Array;
    targetIdentity: Uint8Array;
    sourceBodyIdentities: Uint8Array;
    sourceSubmissionBitmap: number;
    topCount: number;
    targetKind: 'computation' | 'no-result';
    finalitySignature: Uint8Array;
};

type LoadedFinalityState = Readonly<{
    record: ProtectedRecord;
    state: FinalityState;
}>;

type NoResultState = {
    generation: bigint;
    targetIdentity: Uint8Array;
    topCount: number;
    sourceSubmissionBitmap: number;
    acceptedBallotAuthorshipBitmap: number;
};

type LoadedNoResultState = Readonly<{
    record: ProtectedRecord;
    state: NoResultState;
}>;

type VerifiedTallyContext = Readonly<{
    verifiedPreparationRoot: Uint8Array;
    targetBody: Uint8Array;
    targetIdentity: Uint8Array;
    sourceBodyIdentities: Uint8Array;
    sourceSubmissionBitmap: number;
    topCount: number;
    targetKind: 'computation' | 'no-result';
}>;

const zeroVerifiedTallyContext = (context: VerifiedTallyContext): void => {
    context.verifiedPreparationRoot.fill(0);
    context.targetBody.fill(0);
    context.targetIdentity.fill(0);
    context.sourceBodyIdentities.fill(0);
};

class FixedWriter {
    readonly #bytes: Uint8Array;
    #offset = 0;

    constructor(length: number) {
        this.#bytes = new Uint8Array(length);
    }

    writeU8(value: number): void {
        this.#bytes[this.#offset] = value;
        this.#offset += 1;
    }

    writeU16(value: number): void {
        new DataView(this.#bytes.buffer).setUint16(this.#offset, value, true);
        this.#offset += 2;
    }

    writeU64(value: bigint): void {
        new DataView(this.#bytes.buffer).setBigUint64(
            this.#offset,
            value,
            true,
        );
        this.#offset += 8;
    }

    writeFixed(bytes: Uint8Array): void {
        this.#bytes.set(bytes, this.#offset);
        this.#offset += bytes.byteLength;
    }

    finish(): Uint8Array {
        if (this.#offset !== this.#bytes.byteLength) {
            this.#bytes.fill(0);
            throw new Error('The fixed worker record length is inconsistent.');
        }
        return this.#bytes;
    }
}

class FixedReader {
    #offset = 0;

    constructor(private readonly bytes: Uint8Array) {}

    readU8(): number {
        return this.readFixed(1)[0] ?? 0;
    }

    readU16(): number {
        const bytes = this.readFixed(2);
        return new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength,
        ).getUint16(0, true);
    }

    readU64(): bigint {
        const bytes = this.readFixed(8);
        return new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength,
        ).getBigUint64(0, true);
    }

    readFixed(length: number): Uint8Array {
        const end = this.#offset + length;
        if (length < 0 || end > this.bytes.byteLength) {
            throw new DurableStateError(
                'CorruptState',
                'The worker state record is truncated.',
            );
        }
        const result = Uint8Array.from(this.bytes.subarray(this.#offset, end));
        this.#offset = end;
        return result;
    }

    finish(): void {
        if (this.#offset !== this.bytes.byteLength) {
            throw new DurableStateError(
                'CorruptState',
                'The worker state record has trailing bytes.',
            );
        }
    }
}

const requireBytes = (
    value: unknown,
    length: number,
    name: string,
): Uint8Array => {
    if (!(value instanceof Uint8Array) || value.byteLength !== length) {
        throw new TypeError(
            `${name} must be a ${String(length)}-byte Uint8Array.`,
        );
    }
    return value;
};

const requirePosition = (value: unknown, name: string): number => {
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value < 0 ||
        value >= completionProfileParticipantCount
    ) {
        throw new TypeError(`${name} is not a completion-profile position.`);
    }
    return value;
};

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    let difference = 0;
    for (let index = 0; index < left.byteLength; index += 1) {
        difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
    }
    return difference === 0;
};

const isZero = (bytes: Uint8Array): boolean => {
    let aggregate = 0;
    for (const byte of bytes) {
        aggregate |= byte;
    }
    return aggregate === 0;
};

const copyActionContext = (
    value: PrivatePreparationActionContext,
): PrivatePreparationActionContext => ({
    actionProposalIdentity: Uint8Array.from(
        requireBytes(
            value.actionProposalIdentity,
            identityByteLength,
            'actionProposalIdentity',
        ),
    ),
    actionDefinitionIdentity: Uint8Array.from(
        requireBytes(
            value.actionDefinitionIdentity,
            identityByteLength,
            'actionDefinitionIdentity',
        ),
    ),
    predecessorIdentity: Uint8Array.from(
        requireBytes(
            value.predecessorIdentity,
            identityByteLength,
            'predecessorIdentity',
        ),
    ),
    participantPosition: requirePosition(
        value.participantPosition,
        'participantPosition',
    ),
});

const requireUnsigned16 = (value: unknown, name: string): number => {
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value < 0 ||
        value > 0xffff
    ) {
        throw new TypeError(`${name} must be an unsigned 16-bit integer.`);
    }
    return value;
};

const copyCanonicalRosterBytes = (bytes: Uint8Array): Uint8Array =>
    Uint8Array.from(
        requireBytes(bytes, completionRosterByteLength, 'canonicalRosterBytes'),
    );

const copyPreparationParents = (
    parents: readonly PreparationParentCarrier[],
): PreparationParentCarrier[] => {
    if (parents.length !== completionProfileParticipantCount) {
        throw new TypeError(
            'preparationParents must contain the complete roster.',
        );
    }
    return parents.map((parent, position) => ({
        body: Uint8Array.from(
            requireBytes(
                parent.body,
                preparationParentBodyByteLength(
                    completionProfileParticipantCount,
                ),
                `preparationParents[${String(position)}].body`,
            ),
        ),
        signature: Uint8Array.from(
            requireBytes(
                parent.signature,
                actionSignatureCarrierByteLength,
                `preparationParents[${String(position)}].signature`,
            ),
        ),
    }));
};

const copySourcePublicationChoice = (
    choice: SourcePublicationChoice,
): SourcePublicationChoice => {
    if (choice.declaration === 'abstain') {
        return { declaration: 'abstain' };
    }
    if (choice.declaration !== 'submit') {
        throw new TypeError('The source publication choice is invalid.');
    }
    const scoreEncodings = Uint8Array.from(choice.scoreEncodings);
    if (
        scoreEncodings.byteLength !== sourceScoreEncodingCount ||
        scoreEncodings.some((score) => score > 0x0f)
    ) {
        scoreEncodings.fill(0);
        throw new TypeError('The source score encodings are invalid.');
    }
    return { declaration: 'submit', scoreEncodings };
};

const copySourceCarriers = (
    sources: readonly SourceCarrier[],
): SourceCarrier[] => {
    if (sources.length !== completionProfileParticipantCount) {
        throw new TypeError('sources must contain the complete roster.');
    }
    return sources.map((source, position) => {
        if (
            source.declaration !== 'abstain' &&
            source.declaration !== 'submit'
        ) {
            throw new TypeError(
                `sources[${String(position)}] has an invalid declaration.`,
            );
        }
        return {
            declaration: source.declaration,
            body: Uint8Array.from(
                requireBytes(
                    source.body,
                    source.declaration === 'submit'
                        ? submittedSourceBodyByteLength
                        : abstentionSourceBodyByteLength,
                    `sources[${String(position)}].body`,
                ),
            ),
            signature: Uint8Array.from(
                requireBytes(
                    source.signature,
                    actionSignatureCarrierByteLength,
                    `sources[${String(position)}].signature`,
                ),
            ),
        };
    });
};

const copyFinalitySignatures = (
    signatures: readonly FinalitySignatureCarrier[],
): FinalitySignatureCarrier[] => {
    if (
        signatures.length < 8 ||
        signatures.length > completionProfileParticipantCount
    ) {
        throw new TypeError(
            'finalitySignatures must contain one completion-profile quorum.',
        );
    }
    return signatures.map((carrier, index) => ({
        signerPosition: requirePosition(
            carrier.signerPosition,
            `finalitySignatures[${String(index)}].signerPosition`,
        ),
        signature: Uint8Array.from(
            requireBytes(
                carrier.signature,
                actionSignatureCarrierByteLength,
                `finalitySignatures[${String(index)}].signature`,
            ),
        ),
    }));
};

const randomBytes = (length: number): Uint8Array => {
    const output = new Uint8Array(length);
    for (let offset = 0; offset < output.byteLength; offset += 65_536) {
        crypto.getRandomValues(
            output.subarray(offset, Math.min(offset + 65_536, output.length)),
        );
    }
    return output;
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const actionIdentifier = (
    configuration: WorkerConfiguration,
    action: PrivatePreparationActionContext,
): string =>
    `action.${bytesToHex(configuration.runtimeIdentity)}.${bytesToHex(
        action.actionProposalIdentity,
    )}.${String(action.participantPosition)}`;

const preparationIdentifier = (
    configuration: WorkerConfiguration,
    action: PrivatePreparationActionContext,
): string =>
    `preparation.${bytesToHex(configuration.runtimeIdentity)}.${bytesToHex(
        action.actionProposalIdentity,
    )}.${String(action.participantPosition)}`;

const privatePreparationSlotIdentifier = (
    configuration: WorkerConfiguration,
    action: PrivatePreparationActionContext,
    senderPosition: number,
): string =>
    `private-preparation-slot.${bytesToHex(
        configuration.runtimeIdentity,
    )}.${bytesToHex(action.actionProposalIdentity)}.${String(
        action.participantPosition,
    )}.${String(senderPosition)}`;

const sourceIdentifier = (
    configuration: WorkerConfiguration,
    action: PrivatePreparationActionContext,
): string =>
    `source.${bytesToHex(configuration.runtimeIdentity)}.${bytesToHex(
        action.actionProposalIdentity,
    )}.${String(action.participantPosition)}`;

const finalityIdentifier = (
    configuration: WorkerConfiguration,
    action: PrivatePreparationActionContext,
): string =>
    `finality.${bytesToHex(configuration.runtimeIdentity)}.${bytesToHex(
        action.actionProposalIdentity,
    )}.${String(action.participantPosition)}`;

const noResultIdentifier = (
    configuration: WorkerConfiguration,
    action: PrivatePreparationActionContext,
): string =>
    `no-result.${bytesToHex(configuration.runtimeIdentity)}.${bytesToHex(
        action.actionProposalIdentity,
    )}.${String(action.participantPosition)}`;

const remotePositions = (localPosition: number): number[] =>
    Array.from(
        { length: completionProfileParticipantCount },
        (_, position) => position,
    ).filter((position) => position !== localPosition);

const copyPublishedPreparationPackage = (
    state: PreparationState,
): PublishedPreparationPackage => ({
    parentBody: Uint8Array.from(state.parentBody),
    parentSignature: Uint8Array.from(state.parentSignature),
    privateBodies: state.privateBodies.map((body) => Uint8Array.from(body)),
});

const copyPublishedSourcePackage = (
    state: SourceState,
): PublishedSourcePackage => ({
    sourceBody: Uint8Array.from(state.sourceBody),
    sourceSignature: Uint8Array.from(state.sourceSignature),
});

const copyPublishedFinalityPackage = (
    state: FinalityState,
): PublishedFinalityPackage => ({
    targetBody: Uint8Array.from(state.targetBody),
    targetIdentity: Uint8Array.from(state.targetIdentity),
    sourceSubmissionBitmap: state.sourceSubmissionBitmap,
    topCount: state.topCount,
    targetKind: state.targetKind,
    finalitySignature: Uint8Array.from(state.finalitySignature),
});

const copyTallyEvaluationProgress = (
    state: NoResultState,
    resources: KernelResourceMeasurement,
): TallyEvaluationProgress => ({
    kind: 'no-result',
    acceptedBallotAuthorshipBitmap: state.acceptedBallotAuthorshipBitmap,
    resources,
});

const encodeLocalRecordContext = (context: LocalRecordContext): Uint8Array => {
    const writer = new FixedWriter(localContextByteLength);
    const domain = new TextEncoder().encode(localContextDomain);
    if (domain.byteLength > localContextDomainByteLength) {
        throw new Error('The local record domain is too long.');
    }
    const paddedDomain = new Uint8Array(localContextDomainByteLength);
    paddedDomain.set(domain);
    writer.writeFixed(paddedDomain);
    paddedDomain.fill(0);
    writer.writeFixed(context.runtimeIdentity);
    writer.writeFixed(context.candidateBuildIdentity);
    writer.writeFixed(context.actionProposalIdentity);
    writer.writeFixed(context.actionDefinitionIdentity);
    writer.writeFixed(context.rosterIdentity);
    writer.writeFixed(context.predecessorIdentity);
    writer.writeU16(context.participantPosition);
    writer.writeU16(context.objectKind);
    writer.writeU64(context.generation);
    writer.writeU16(context.peerPosition);
    writer.writeU64(context.operationOrdinal);
    return writer.finish();
};

const decodeLocalRecordContext = (bytes: ArrayBuffer): LocalRecordContext => {
    const reader = new FixedReader(new Uint8Array(bytes));
    const actualDomain = reader.readFixed(localContextDomainByteLength);
    const expectedDomain = new Uint8Array(localContextDomainByteLength);
    expectedDomain.set(new TextEncoder().encode(localContextDomain));
    if (!bytesEqual(actualDomain, expectedDomain)) {
        throw new DurableStateError(
            'CorruptState',
            'The local record has the wrong domain.',
        );
    }
    const context = {
        runtimeIdentity: reader.readFixed(identityByteLength),
        candidateBuildIdentity: reader.readFixed(identityByteLength),
        actionProposalIdentity: reader.readFixed(identityByteLength),
        actionDefinitionIdentity: reader.readFixed(identityByteLength),
        rosterIdentity: reader.readFixed(identityByteLength),
        predecessorIdentity: reader.readFixed(identityByteLength),
        participantPosition: reader.readU16(),
        objectKind: reader.readU16(),
        generation: reader.readU64(),
        peerPosition: reader.readU16(),
        operationOrdinal: reader.readU64(),
    };
    reader.finish();
    return context;
};

const actionStateByteLength =
    1 +
    1 +
    2 +
    8 +
    6 * identityByteLength +
    completionRosterByteLength +
    signaturePurposeCount * identityByteLength +
    actionSignatureSecretKeyByteLength +
    pairDecryptionKeyByteLength;

const encodeActionState = (state: ActionState): Uint8Array => {
    const writer = new FixedWriter(actionStateByteLength);
    writer.writeU8(4);
    writer.writeU8(state.phase);
    writer.writeU16(state.participantPosition);
    writer.writeU64(state.generation);
    writer.writeFixed(state.runtimeIdentity);
    writer.writeFixed(state.candidateBuildIdentity);
    writer.writeFixed(state.actionProposalIdentity);
    writer.writeFixed(state.actionDefinitionIdentity);
    writer.writeFixed(state.rosterIdentity);
    writer.writeFixed(state.predecessorIdentity);
    writer.writeFixed(state.canonicalRosterBytes);
    for (const bodyIdentity of state.signatureBodyIdentities) {
        writer.writeFixed(bodyIdentity);
    }
    writer.writeFixed(state.signingSecretKey);
    writer.writeFixed(state.mailboxDecapsulationKey);
    return writer.finish();
};

const decodeActionState = (bytes: Uint8Array): ActionState => {
    if (bytes.byteLength !== actionStateByteLength) {
        throw new DurableStateError(
            'CorruptState',
            'The action state has the wrong byte length.',
        );
    }
    const reader = new FixedReader(bytes);
    if (reader.readU8() !== 4) {
        throw new DurableStateError(
            'CorruptState',
            'The action state has the wrong version.',
        );
    }
    const phase = reader.readU8();
    if (phase !== rosterBoundActionPhase) {
        throw new DurableStateError(
            'CorruptState',
            'The action state has an invalid phase.',
        );
    }
    const state: ActionState = {
        phase,
        participantPosition: reader.readU16(),
        generation: reader.readU64(),
        runtimeIdentity: reader.readFixed(identityByteLength),
        candidateBuildIdentity: reader.readFixed(identityByteLength),
        actionProposalIdentity: reader.readFixed(identityByteLength),
        actionDefinitionIdentity: reader.readFixed(identityByteLength),
        rosterIdentity: reader.readFixed(identityByteLength),
        predecessorIdentity: reader.readFixed(identityByteLength),
        canonicalRosterBytes: reader.readFixed(completionRosterByteLength),
        signatureBodyIdentities: Array.from(
            { length: signaturePurposeCount },
            () => reader.readFixed(identityByteLength),
        ),
        signingSecretKey: reader.readFixed(actionSignatureSecretKeyByteLength),
        mailboxDecapsulationKey: reader.readFixed(pairDecryptionKeyByteLength),
    };
    reader.finish();
    return state;
};

const zeroActionState = (state: ActionState): void => {
    state.signingSecretKey.fill(0);
    state.mailboxDecapsulationKey.fill(0);
};

const remoteParticipantCount = completionProfileParticipantCount - 1;
const completionPreparationParentBodyByteLength =
    preparationParentBodyByteLength(completionProfileParticipantCount);
const preparationStateByteLength =
    1 +
    1 +
    8 +
    2 +
    identityByteLength +
    completionPreparationParentBodyByteLength +
    actionSignatureCarrierByteLength +
    remoteParticipantCount * identityByteLength +
    remoteParticipantCount * privatePreparationBodyByteLength +
    preparationContributionOpeningVectorByteLength +
    preparationPairwiseMasterVectorByteLength;

const encodePreparationState = (state: PreparationState): Uint8Array => {
    const writer = new FixedWriter(preparationStateByteLength);
    writer.writeU8(3);
    writer.writeU8(state.phase);
    writer.writeU64(state.generation);
    writer.writeU16(state.preparationAttempt);
    writer.writeFixed(state.parentIdentity);
    writer.writeFixed(state.parentBody);
    writer.writeFixed(state.parentSignature);
    for (const identity of state.privateBodyIdentities) {
        writer.writeFixed(identity);
    }
    for (const body of state.privateBodies) {
        writer.writeFixed(body);
    }
    writer.writeFixed(state.contributionOpenings);
    writer.writeFixed(state.pairwiseMasters);
    return writer.finish();
};

const decodePreparationState = (bytes: Uint8Array): PreparationState => {
    if (bytes.byteLength !== preparationStateByteLength) {
        throw new DurableStateError(
            'CorruptState',
            'The retained preparation has the wrong byte length.',
        );
    }
    const reader = new FixedReader(bytes);
    if (reader.readU8() !== 3) {
        throw new DurableStateError(
            'CorruptState',
            'The retained preparation has the wrong version.',
        );
    }
    const phase = reader.readU8();
    if (
        phase !== unsignedPreparationPhase &&
        phase !== publishedPreparationPhase
    ) {
        throw new DurableStateError(
            'CorruptState',
            'The retained preparation has an invalid phase.',
        );
    }
    const state: PreparationState = {
        phase,
        generation: reader.readU64(),
        preparationAttempt: reader.readU16(),
        parentIdentity: reader.readFixed(identityByteLength),
        parentBody: reader.readFixed(completionPreparationParentBodyByteLength),
        parentSignature: reader.readFixed(actionSignatureCarrierByteLength),
        privateBodyIdentities: Array.from(
            { length: remoteParticipantCount },
            () => reader.readFixed(identityByteLength),
        ),
        privateBodies: Array.from({ length: remoteParticipantCount }, () =>
            reader.readFixed(privatePreparationBodyByteLength),
        ),
        contributionOpenings: reader.readFixed(
            preparationContributionOpeningVectorByteLength,
        ),
        pairwiseMasters: reader.readFixed(
            preparationPairwiseMasterVectorByteLength,
        ),
    };
    reader.finish();
    if (
        state.phase === unsignedPreparationPhase &&
        !isZero(state.parentSignature)
    ) {
        throw new DurableStateError(
            'CorruptState',
            'The retained preparation signature state is inconsistent.',
        );
    }
    return state;
};

const zeroPreparationState = (state: PreparationState): void => {
    state.contributionOpenings.fill(0);
    state.pairwiseMasters.fill(0);
};

const sourceStateByteLength =
    1 +
    1 +
    8 +
    2 +
    identityByteLength +
    1 +
    sourceScoreEncodingCount +
    submittedSourceBodyByteLength +
    identityByteLength +
    actionSignatureCarrierByteLength +
    heldSubsetKeyVectorByteLength;

const encodeSourceState = (state: SourceState): Uint8Array => {
    const expectedBodyByteLength =
        state.declaration === 'submit'
            ? submittedSourceBodyByteLength
            : abstentionSourceBodyByteLength;
    if (
        state.sourceBody.byteLength !== expectedBodyByteLength ||
        (state.declaration === 'abstain' && !isZero(state.scoreEncodings)) ||
        state.scoreEncodings.byteLength !== sourceScoreEncodingCount ||
        state.scoreEncodings.some((score) => score > 0x0f)
    ) {
        throw new DurableStateError(
            'CorruptState',
            'The retained source choice and body length are inconsistent.',
        );
    }
    const writer = new FixedWriter(sourceStateByteLength);
    writer.writeU8(5);
    writer.writeU8(state.phase);
    writer.writeU64(state.generation);
    writer.writeU16(state.preparationAttempt);
    writer.writeFixed(state.verifiedPreparationRoot);
    writer.writeU8(state.declaration === 'submit' ? 2 : 1);
    writer.writeFixed(state.scoreEncodings);
    const paddedBody = new Uint8Array(submittedSourceBodyByteLength);
    paddedBody.set(state.sourceBody);
    writer.writeFixed(paddedBody);
    paddedBody.fill(0);
    writer.writeFixed(state.sourceBodyIdentity);
    writer.writeFixed(state.sourceSignature);
    writer.writeFixed(state.heldSubsetKeys);
    return writer.finish();
};

const decodeSourceState = (bytes: Uint8Array): SourceState => {
    if (bytes.byteLength !== sourceStateByteLength) {
        throw new DurableStateError(
            'CorruptState',
            'The retained source has the wrong byte length.',
        );
    }
    const reader = new FixedReader(bytes);
    if (reader.readU8() !== 5) {
        throw new DurableStateError(
            'CorruptState',
            'The retained source has the wrong version.',
        );
    }
    const phase = reader.readU8();
    if (phase !== unsignedSourcePhase && phase !== publishedSourcePhase) {
        throw new DurableStateError(
            'CorruptState',
            'The retained source has an invalid phase.',
        );
    }
    const generation = reader.readU64();
    const preparationAttempt = reader.readU16();
    const verifiedPreparationRoot = reader.readFixed(identityByteLength);
    const declarationCode = reader.readU8();
    const declaration: SourceDeclaration =
        declarationCode === 1
            ? 'abstain'
            : declarationCode === 2
              ? 'submit'
              : (() => {
                    throw new DurableStateError(
                        'CorruptState',
                        'The retained source has an invalid declaration.',
                    );
                })();
    const scoreEncodings = reader.readFixed(sourceScoreEncodingCount);
    if (
        scoreEncodings.some((score) => score > 0x0f) ||
        (declaration === 'abstain' && !isZero(scoreEncodings))
    ) {
        throw new DurableStateError(
            'CorruptState',
            'The retained source has an invalid private input.',
        );
    }
    const paddedBody = reader.readFixed(submittedSourceBodyByteLength);
    const sourceBodyByteLength =
        declaration === 'submit'
            ? submittedSourceBodyByteLength
            : abstentionSourceBodyByteLength;
    if (!isZero(paddedBody.subarray(sourceBodyByteLength))) {
        paddedBody.fill(0);
        throw new DurableStateError(
            'CorruptState',
            'The retained source has noncanonical body padding.',
        );
    }
    const sourceBody = Uint8Array.from(
        paddedBody.subarray(0, sourceBodyByteLength),
    );
    paddedBody.fill(0);
    const state: SourceState = {
        phase,
        generation,
        preparationAttempt,
        verifiedPreparationRoot,
        declaration,
        scoreEncodings,
        sourceBody,
        sourceBodyIdentity: reader.readFixed(identityByteLength),
        sourceSignature: reader.readFixed(actionSignatureCarrierByteLength),
        heldSubsetKeys: reader.readFixed(heldSubsetKeyVectorByteLength),
    };
    reader.finish();
    if (state.phase === unsignedSourcePhase && !isZero(state.sourceSignature)) {
        zeroSourceState(state);
        throw new DurableStateError(
            'CorruptState',
            'The unsigned source contains a signature.',
        );
    }
    return state;
};

const zeroSourceState = (state: SourceState): void => {
    state.verifiedPreparationRoot.fill(0);
    state.scoreEncodings.fill(0);
    state.sourceBody.fill(0);
    state.sourceBodyIdentity.fill(0);
    state.sourceSignature.fill(0);
    state.heldSubsetKeys.fill(0);
};

const sourceBodyIdentityVectorByteLength =
    completionProfileParticipantCount * identityByteLength;
const finalityStateByteLength =
    1 +
    1 +
    8 +
    2 +
    identityByteLength +
    finalityTargetBodyByteLength +
    identityByteLength +
    sourceBodyIdentityVectorByteLength +
    2 +
    2 +
    1 +
    actionSignatureCarrierByteLength;

const finalityTargetKindCode = (
    targetKind: FinalityState['targetKind'],
): number => (targetKind === 'computation' ? 1 : 2);

const finalityTargetKindFromCode = (
    code: number,
): FinalityState['targetKind'] => {
    if (code === 1) {
        return 'computation';
    }
    if (code === 2) {
        return 'no-result';
    }
    throw new DurableStateError(
        'CorruptState',
        'The retained finality target kind is invalid.',
    );
};

const encodeFinalityState = (state: FinalityState): Uint8Array => {
    const writer = new FixedWriter(finalityStateByteLength);
    writer.writeU8(2);
    writer.writeU8(state.phase);
    writer.writeU64(state.generation);
    writer.writeU16(state.preparationAttempt);
    writer.writeFixed(state.verifiedPreparationRoot);
    writer.writeFixed(state.targetBody);
    writer.writeFixed(state.targetIdentity);
    writer.writeFixed(state.sourceBodyIdentities);
    writer.writeU16(state.sourceSubmissionBitmap);
    writer.writeU16(state.topCount);
    writer.writeU8(finalityTargetKindCode(state.targetKind));
    writer.writeFixed(state.finalitySignature);
    return writer.finish();
};

const decodeFinalityState = (bytes: Uint8Array): FinalityState => {
    if (bytes.byteLength !== finalityStateByteLength) {
        throw new DurableStateError(
            'CorruptState',
            'The retained finality state has the wrong byte length.',
        );
    }
    const reader = new FixedReader(bytes);
    if (reader.readU8() !== 2) {
        throw new DurableStateError(
            'CorruptState',
            'The retained finality state has the wrong version.',
        );
    }
    const phase = reader.readU8();
    if (phase !== unsignedFinalityPhase && phase !== publishedFinalityPhase) {
        throw new DurableStateError(
            'CorruptState',
            'The retained finality state has an invalid phase.',
        );
    }
    const state: FinalityState = {
        phase,
        generation: reader.readU64(),
        preparationAttempt: reader.readU16(),
        verifiedPreparationRoot: reader.readFixed(identityByteLength),
        targetBody: reader.readFixed(finalityTargetBodyByteLength),
        targetIdentity: reader.readFixed(identityByteLength),
        sourceBodyIdentities: reader.readFixed(
            sourceBodyIdentityVectorByteLength,
        ),
        sourceSubmissionBitmap: reader.readU16(),
        topCount: reader.readU16(),
        targetKind: finalityTargetKindFromCode(reader.readU8()),
        finalitySignature: reader.readFixed(actionSignatureCarrierByteLength),
    };
    reader.finish();
    return state;
};

const zeroFinalityState = (state: FinalityState): void => {
    state.verifiedPreparationRoot.fill(0);
    state.targetBody.fill(0);
    state.targetIdentity.fill(0);
    state.sourceBodyIdentities.fill(0);
    state.finalitySignature.fill(0);
};

const noResultStateByteLength = 1 + 8 + identityByteLength + 2 + 2 + 2;

const encodeNoResultState = (state: NoResultState): Uint8Array => {
    const writer = new FixedWriter(noResultStateByteLength);
    writer.writeU8(1);
    writer.writeU64(state.generation);
    writer.writeFixed(state.targetIdentity);
    writer.writeU16(state.topCount);
    writer.writeU16(state.sourceSubmissionBitmap);
    writer.writeU16(state.acceptedBallotAuthorshipBitmap);
    return writer.finish();
};

const decodeNoResultState = (bytes: Uint8Array): NoResultState => {
    if (bytes.byteLength !== noResultStateByteLength) {
        throw new DurableStateError(
            'CorruptState',
            'The retained no-result state has the wrong byte length.',
        );
    }
    const reader = new FixedReader(bytes);
    if (reader.readU8() !== 1) {
        throw new DurableStateError(
            'CorruptState',
            'The retained no-result state has the wrong version.',
        );
    }
    const state: NoResultState = {
        generation: reader.readU64(),
        targetIdentity: reader.readFixed(identityByteLength),
        topCount: reader.readU16(),
        sourceSubmissionBitmap: reader.readU16(),
        acceptedBallotAuthorshipBitmap: reader.readU16(),
    };
    reader.finish();
    if (state.acceptedBallotAuthorshipBitmap !== 0) {
        zeroNoResultState(state);
        throw new DurableStateError(
            'CorruptState',
            'The retained no-result state claims accepted ballots.',
        );
    }
    return state;
};

const zeroNoResultState = (state: NoResultState): void => {
    state.targetIdentity.fill(0);
};

const privatePreparationSlotStateByteLength =
    1 + 1 + 8 + 2 + 2 + 3 * identityByteLength + preparationPlaintextByteLength;

const encodePrivatePreparationSlotState = (
    state: PrivatePreparationSlotState,
): Uint8Array => {
    const writer = new FixedWriter(privatePreparationSlotStateByteLength);
    writer.writeU8(1);
    writer.writeU8(state.phase);
    writer.writeU64(state.generation);
    writer.writeU16(state.preparationAttempt);
    writer.writeU16(state.senderPosition);
    writer.writeFixed(state.parentIdentity);
    writer.writeFixed(state.bodyIdentity);
    writer.writeFixed(state.verifiedPlaintextIdentity);
    writer.writeFixed(state.plaintext);
    return writer.finish();
};

const decodePrivatePreparationSlotState = (
    bytes: Uint8Array,
): PrivatePreparationSlotState => {
    if (bytes.byteLength !== privatePreparationSlotStateByteLength) {
        throw new DurableStateError(
            'CorruptState',
            'The private-preparation slot has the wrong byte length.',
        );
    }
    const reader = new FixedReader(bytes);
    if (reader.readU8() !== 1) {
        throw new DurableStateError(
            'CorruptState',
            'The private-preparation slot has the wrong version.',
        );
    }
    const phase = reader.readU8();
    if (
        phase !== consumedPrivatePreparationPhase &&
        phase !== resolvedPrivatePreparationPhase &&
        phase !== burnedPrivatePreparationPhase
    ) {
        throw new DurableStateError(
            'CorruptState',
            'The private-preparation slot has an invalid phase.',
        );
    }
    const state: PrivatePreparationSlotState = {
        phase,
        generation: reader.readU64(),
        preparationAttempt: reader.readU16(),
        senderPosition: reader.readU16(),
        parentIdentity: reader.readFixed(identityByteLength),
        bodyIdentity: reader.readFixed(identityByteLength),
        verifiedPlaintextIdentity: reader.readFixed(identityByteLength),
        plaintext: reader.readFixed(preparationPlaintextByteLength),
    };
    reader.finish();
    if (
        state.phase !== resolvedPrivatePreparationPhase &&
        (!isZero(state.verifiedPlaintextIdentity) || !isZero(state.plaintext))
    ) {
        throw new DurableStateError(
            'CorruptState',
            'The unopened private-preparation slot contains resolved material.',
        );
    }
    return state;
};

const zeroPrivatePreparationSlotState = (
    state: PrivatePreparationSlotState,
): void => {
    state.plaintext.fill(0);
};

const actionLocalContext = (
    configuration: WorkerConfiguration,
    action: PrivatePreparationActionContext,
    rosterIdentity: Uint8Array,
    generation: bigint,
): LocalRecordContext => ({
    runtimeIdentity: configuration.runtimeIdentity,
    candidateBuildIdentity: configuration.candidateBuildIdentity,
    actionProposalIdentity: action.actionProposalIdentity,
    actionDefinitionIdentity: action.actionDefinitionIdentity,
    rosterIdentity: rosterIdentity,
    predecessorIdentity: action.predecessorIdentity,
    participantPosition: action.participantPosition,
    objectKind: actionStateKind,
    generation,
    peerPosition: noPeerPosition,
    operationOrdinal: 0n,
});

const preparationLocalContext = (
    configuration: WorkerConfiguration,
    action: PrivatePreparationActionContext,
    rosterIdentity: Uint8Array,
    generation: bigint,
    preparationAttempt: number,
): LocalRecordContext => ({
    runtimeIdentity: configuration.runtimeIdentity,
    candidateBuildIdentity: configuration.candidateBuildIdentity,
    actionProposalIdentity: action.actionProposalIdentity,
    actionDefinitionIdentity: action.actionDefinitionIdentity,
    rosterIdentity: rosterIdentity,
    predecessorIdentity: action.predecessorIdentity,
    participantPosition: action.participantPosition,
    objectKind: preparationStateKind,
    generation,
    peerPosition: noPeerPosition,
    operationOrdinal: BigInt(preparationAttempt),
});

const sourceLocalContext = (
    configuration: WorkerConfiguration,
    action: PrivatePreparationActionContext,
    rosterIdentity: Uint8Array,
    generation: bigint,
): LocalRecordContext => ({
    runtimeIdentity: configuration.runtimeIdentity,
    candidateBuildIdentity: configuration.candidateBuildIdentity,
    actionProposalIdentity: action.actionProposalIdentity,
    actionDefinitionIdentity: action.actionDefinitionIdentity,
    rosterIdentity: rosterIdentity,
    predecessorIdentity: action.predecessorIdentity,
    participantPosition: action.participantPosition,
    objectKind: sourceStateKind,
    generation,
    peerPosition: noPeerPosition,
    operationOrdinal: sourceOperationOrdinal,
});

const terminalLocalContext = (
    configuration: WorkerConfiguration,
    action: PrivatePreparationActionContext,
    rosterIdentity: Uint8Array,
    generation: bigint,
    objectKind: number,
): LocalRecordContext => ({
    runtimeIdentity: configuration.runtimeIdentity,
    candidateBuildIdentity: configuration.candidateBuildIdentity,
    actionProposalIdentity: action.actionProposalIdentity,
    actionDefinitionIdentity: action.actionDefinitionIdentity,
    rosterIdentity: rosterIdentity,
    predecessorIdentity: action.predecessorIdentity,
    participantPosition: action.participantPosition,
    objectKind,
    generation,
    peerPosition: noPeerPosition,
    operationOrdinal: 0n,
});

const assertTerminalLocalContext = (
    generation: bigint,
    localContext: LocalRecordContext,
    configuration: WorkerConfiguration,
    action: PrivatePreparationActionContext,
    rosterIdentity: Uint8Array,
    objectKind: number,
): void => {
    if (
        localContext.generation !== generation ||
        localContext.objectKind !== objectKind ||
        localContext.peerPosition !== noPeerPosition ||
        localContext.operationOrdinal !== 0n ||
        localContext.participantPosition !== action.participantPosition ||
        !bytesEqual(
            localContext.runtimeIdentity,
            configuration.runtimeIdentity,
        ) ||
        !bytesEqual(
            localContext.candidateBuildIdentity,
            configuration.candidateBuildIdentity,
        ) ||
        !bytesEqual(
            localContext.actionProposalIdentity,
            action.actionProposalIdentity,
        ) ||
        !bytesEqual(
            localContext.actionDefinitionIdentity,
            action.actionDefinitionIdentity,
        ) ||
        !bytesEqual(localContext.rosterIdentity, rosterIdentity) ||
        !bytesEqual(
            localContext.predecessorIdentity,
            action.predecessorIdentity,
        )
    ) {
        throw new DurableStateError(
            'StateLost',
            'The retained terminal state does not match its authenticated context.',
        );
    }
};

const privatePreparationSlotLocalContext = (
    configuration: WorkerConfiguration,
    action: PrivatePreparationActionContext,
    rosterIdentity: Uint8Array,
    generation: bigint,
    senderPosition: number,
): LocalRecordContext => ({
    runtimeIdentity: configuration.runtimeIdentity,
    candidateBuildIdentity: configuration.candidateBuildIdentity,
    actionProposalIdentity: action.actionProposalIdentity,
    actionDefinitionIdentity: action.actionDefinitionIdentity,
    rosterIdentity: rosterIdentity,
    predecessorIdentity: action.predecessorIdentity,
    participantPosition: action.participantPosition,
    objectKind: privatePreparationSlotStateKind,
    generation,
    peerPosition: senderPosition,
    operationOrdinal: privatePreparationOperationOrdinal,
});

const assertActionStateContext = (
    state: ActionState,
    localContext: LocalRecordContext,
    configuration: WorkerConfiguration,
    action: PrivatePreparationActionContext,
): void => {
    if (
        state.phase !== rosterBoundActionPhase ||
        state.generation !== localContext.generation ||
        state.participantPosition !== action.participantPosition ||
        localContext.participantPosition !== action.participantPosition ||
        localContext.objectKind !== actionStateKind ||
        localContext.peerPosition !== noPeerPosition ||
        localContext.operationOrdinal !== 0n ||
        !bytesEqual(state.runtimeIdentity, configuration.runtimeIdentity) ||
        !bytesEqual(
            localContext.runtimeIdentity,
            configuration.runtimeIdentity,
        ) ||
        !bytesEqual(
            state.candidateBuildIdentity,
            configuration.candidateBuildIdentity,
        ) ||
        !bytesEqual(
            localContext.candidateBuildIdentity,
            configuration.candidateBuildIdentity,
        ) ||
        !bytesEqual(
            state.actionProposalIdentity,
            action.actionProposalIdentity,
        ) ||
        !bytesEqual(
            localContext.actionProposalIdentity,
            action.actionProposalIdentity,
        ) ||
        !bytesEqual(
            state.actionDefinitionIdentity,
            action.actionDefinitionIdentity,
        ) ||
        !bytesEqual(
            localContext.actionDefinitionIdentity,
            action.actionDefinitionIdentity,
        ) ||
        !bytesEqual(state.predecessorIdentity, action.predecessorIdentity) ||
        !bytesEqual(
            localContext.predecessorIdentity,
            action.predecessorIdentity,
        ) ||
        !bytesEqual(state.rosterIdentity, localContext.rosterIdentity) ||
        isZero(state.rosterIdentity)
    ) {
        throw new DurableStateError(
            'StateLost',
            'The retained action state does not match its authenticated context.',
        );
    }
};

class PrivatePreparationWorkerRuntime {
    private constructor(
        private readonly configuration: WorkerConfiguration,
        private readonly durableState: PrivatePreparationDurableState,
        private readonly constructionKernelRuntime: ConstructionKernelCommandRuntime,
        private readonly actionSignatureRuntime: ActionSignatureRuntime,
        private readonly finalityRuntime: ReturnType<
            typeof openFinalityRuntime
        >,
        private readonly preparationMaterialRuntime: PreparationMaterialRuntime,
        private readonly preparationParentRuntime: PreparationParentRuntime,
        private readonly privatePreparationBodyRuntime: PrivatePreparationBodyRuntime,
        private readonly rosterRuntime: RosterRuntime,
        private readonly sourceRuntime: SourceRuntime,
    ) {}

    static async create(
        initialization: PrivatePreparationWorkerInitialization,
        persistentStorageRequired: boolean,
        unpinnedKernelAllowed: boolean,
        afterDurableConsume?: () => Promise<void> | void,
        afterDurableSourceBind?: () => Promise<void> | void,
    ): Promise<PrivatePreparationWorkerRuntime> {
        const runtimeIdentity = Uint8Array.from(
            requireBytes(
                initialization.runtimeIdentity,
                identityByteLength,
                'runtimeIdentity',
            ),
        );
        const candidateBuildIdentity = Uint8Array.from(
            requireBytes(
                initialization.candidateBuildIdentity,
                identityByteLength,
                'candidateBuildIdentity',
            ),
        );
        let kernelUrl: URL;
        try {
            kernelUrl = new URL(initialization.kernelUrl);
        } catch {
            throw new TypeError('kernelUrl is invalid.');
        }
        const kernelOptions: FoundationKernelLoaderOptions =
            initialization.kernelOptions;
        if (
            !unpinnedKernelAllowed &&
            (kernelOptions.allowUnpinnedKernel === true ||
                kernelOptions.expectedKernelSha256Hex === undefined)
        ) {
            throw new TypeError(
                'The production worker requires a pinned kernel identity.',
            );
        }
        const [durableState, kernel] = await Promise.all([
            PrivatePreparationDurableState.open(
                initialization.databaseName,
                persistentStorageRequired,
            ),
            instantiateConstructionKernelCommandRuntime(
                kernelUrl,
                kernelOptions,
            ),
        ]);
        return new PrivatePreparationWorkerRuntime(
            {
                runtimeIdentity,
                candidateBuildIdentity,
                afterDurableConsume,
                afterDurableSourceBind,
            },
            durableState,
            kernel,
            openActionSignatureRuntime(kernel),
            openFinalityRuntime(kernel),
            openPreparationMaterialRuntime(kernel),
            openPreparationParentRuntime(kernel),
            openPrivatePreparationBodyRuntime(kernel),
            openRosterRuntime(kernel),
            openSourceRuntime(kernel),
        );
    }

    private async ensureRosterBoundAction(
        action: PrivatePreparationActionContext,
        canonicalRosterBytes: Uint8Array,
        signingSecretKey: Uint8Array,
        mailboxDecapsulationKey: Uint8Array,
    ): Promise<void> {
        const rosterIdentity = this.rosterRuntime.verifyCredentials(
            canonicalRosterBytes,
            action.participantPosition,
            signingSecretKey,
            mailboxDecapsulationKey,
        );
        const identifier = actionIdentifier(this.configuration, action);
        const existing = await this.durableState.readProtected(
            'actions',
            identifier,
        );
        if (existing !== undefined) {
            const loaded = await this.loadActionState(action, existing);
            try {
                if (
                    loaded.state.phase !== rosterBoundActionPhase ||
                    !bytesEqual(loaded.state.rosterIdentity, rosterIdentity) ||
                    !bytesEqual(
                        loaded.state.canonicalRosterBytes,
                        canonicalRosterBytes,
                    ) ||
                    !bytesEqual(
                        loaded.state.signingSecretKey,
                        signingSecretKey,
                    ) ||
                    !bytesEqual(
                        loaded.state.mailboxDecapsulationKey,
                        mailboxDecapsulationKey,
                    )
                ) {
                    throw new DurableStateError(
                        'Conflict',
                        'The action is already bound to another roster or credential.',
                    );
                }
                return;
            } finally {
                zeroActionState(loaded.state);
            }
        }

        let rootKey = await this.durableState.readRoot();
        const protectedRecordCount =
            await this.durableState.countProtectedRecords();
        if (rootKey === undefined && protectedRecordCount !== 0) {
            throw new DurableStateError(
                'StateLost',
                'The browser-local root is absent while protected state remains.',
            );
        }
        rootKey ??= await generateBrowserLocalRootKey();
        const state: ActionState = {
            phase: rosterBoundActionPhase,
            generation: 1n,
            runtimeIdentity: this.configuration.runtimeIdentity,
            candidateBuildIdentity: this.configuration.candidateBuildIdentity,
            actionProposalIdentity: action.actionProposalIdentity,
            actionDefinitionIdentity: action.actionDefinitionIdentity,
            rosterIdentity: Uint8Array.from(rosterIdentity),
            predecessorIdentity: action.predecessorIdentity,
            participantPosition: action.participantPosition,
            canonicalRosterBytes: Uint8Array.from(canonicalRosterBytes),
            signatureBodyIdentities: Array.from(
                { length: signaturePurposeCount },
                () => new Uint8Array(identityByteLength),
            ),
            signingSecretKey: Uint8Array.from(signingSecretKey),
            mailboxDecapsulationKey: Uint8Array.from(mailboxDecapsulationKey),
        };
        try {
            const plaintext = encodeActionState(state);
            const context = encodeLocalRecordContext(
                actionLocalContext(
                    this.configuration,
                    action,
                    rosterIdentity,
                    state.generation,
                ),
            );
            let record: ProtectedRecord;
            try {
                record = await createProtectedRecord(
                    identifier,
                    context,
                    plaintext,
                    rootKey,
                );
            } finally {
                plaintext.fill(0);
                context.fill(0);
            }
            if ((await this.durableState.readRoot()) === undefined) {
                await this.durableState.initializeRootAndAction(
                    rootKey,
                    record,
                );
            } else {
                await this.durableState.putIfAbsent('actions', record);
            }
            const retained = await this.durableState.readProtected(
                'actions',
                identifier,
            );
            if (retained === undefined) {
                throw new DurableStateError(
                    'StateLost',
                    'The roster-bound action state disappeared after persistence.',
                );
            }
            const reloaded = await this.loadActionState(action, retained);
            zeroActionState(reloaded.state);
        } finally {
            zeroActionState(state);
            rosterIdentity.fill(0);
        }
    }

    async createPreparationPackage(
        input: PrivatePreparationActionContext & {
            canonicalRosterBytes: Uint8Array;
            signingSecretKey: Uint8Array;
            mailboxDecapsulationKey: Uint8Array;
            preparationAttempt: number;
        },
    ): Promise<PublishedPreparationPackage> {
        const action = copyActionContext(input);
        const canonicalRosterBytes = Uint8Array.from(
            requireBytes(
                input.canonicalRosterBytes,
                completionRosterByteLength,
                'canonicalRosterBytes',
            ),
        );
        const signingSecretKey = Uint8Array.from(
            requireBytes(
                input.signingSecretKey,
                actionSignatureSecretKeyByteLength,
                'signingSecretKey',
            ),
        );
        const mailboxDecapsulationKey = Uint8Array.from(
            requireBytes(
                input.mailboxDecapsulationKey,
                pairDecryptionKeyByteLength,
                'mailboxDecapsulationKey',
            ),
        );
        const preparationAttempt = requireUnsigned16(
            input.preparationAttempt,
            'preparationAttempt',
        );
        return this.durableState
            .exclusive(async () => {
                await this.ensureRosterBoundAction(
                    action,
                    canonicalRosterBytes,
                    signingSecretKey,
                    mailboxDecapsulationKey,
                );
                const actionRecord = await this.durableState.readProtected(
                    'actions',
                    actionIdentifier(this.configuration, action),
                );
                if (actionRecord === undefined) {
                    throw new DurableStateError(
                        'StateLost',
                        'The roster-bound action state is absent for preparation publication.',
                    );
                }
                const loadedAction = await this.loadActionState(
                    action,
                    actionRecord,
                );
                try {
                    this.verifyRosterBoundAction(action, loadedAction.state);
                    const identifier = preparationIdentifier(
                        this.configuration,
                        action,
                    );
                    const existing = await this.durableState.readProtected(
                        'preparations',
                        identifier,
                    );
                    const boundParentIdentity =
                        loadedAction.state.signatureBodyIdentities[0];
                    if (boundParentIdentity === undefined) {
                        throw new DurableStateError(
                            'CorruptState',
                            'The preparation-signature slot is absent.',
                        );
                    }
                    if (existing !== undefined) {
                        if (isZero(boundParentIdentity)) {
                            throw new DurableStateError(
                                'StateLost',
                                'Retained preparation exists without its action-level signature binding.',
                            );
                        }
                        const loadedPreparation =
                            await this.loadPreparationState(
                                action,
                                loadedAction.state.rosterIdentity,
                                existing,
                            );
                        try {
                            if (
                                loadedPreparation.state.preparationAttempt !==
                                    preparationAttempt ||
                                !bytesEqual(
                                    loadedPreparation.state.parentIdentity,
                                    boundParentIdentity,
                                )
                            ) {
                                throw new DurableStateError(
                                    'Conflict',
                                    'The action is already bound to another preparation.',
                                );
                            }
                            this.validatePreparationState(
                                action,
                                canonicalRosterBytes,
                                loadedAction.state,
                                loadedPreparation.state,
                            );
                            if (
                                loadedPreparation.state.phase ===
                                publishedPreparationPhase
                            ) {
                                return copyPublishedPreparationPackage(
                                    loadedPreparation.state,
                                );
                            }
                            return await this.publishRetainedPreparation(
                                action,
                                canonicalRosterBytes,
                                loadedAction,
                                loadedPreparation,
                            );
                        } finally {
                            zeroPreparationState(loadedPreparation.state);
                        }
                    }
                    if (!isZero(boundParentIdentity)) {
                        throw new DurableStateError(
                            'StateLost',
                            'The preparation-signature slot is consumed but its retained package is absent.',
                        );
                    }
                    return await this.createAndPublishPreparation(
                        action,
                        canonicalRosterBytes,
                        preparationAttempt,
                        loadedAction,
                    );
                } finally {
                    zeroActionState(loadedAction.state);
                }
            })
            .finally(() => {
                signingSecretKey.fill(0);
                mailboxDecapsulationKey.fill(0);
            });
    }

    async consumePrivatePreparation(
        input: PrivatePreparationActionContext & {
            canonicalRosterBytes: Uint8Array;
            preparationAttempt: number;
            parentBody: Uint8Array;
            parentSignature: Uint8Array;
            privateBody: Uint8Array;
        },
    ): Promise<PrivatePreparationConsumption> {
        const action = copyActionContext(input);
        const canonicalRosterBytes = copyCanonicalRosterBytes(
            input.canonicalRosterBytes,
        );
        const preparationAttempt = requireUnsigned16(
            input.preparationAttempt,
            'preparationAttempt',
        );
        const parentBody = Uint8Array.from(
            requireBytes(
                input.parentBody,
                completionPreparationParentBodyByteLength,
                'parentBody',
            ),
        );
        const parentSignature = Uint8Array.from(
            requireBytes(
                input.parentSignature,
                actionSignatureCarrierByteLength,
                'parentSignature',
            ),
        );
        const privateBody = Uint8Array.from(
            requireBytes(
                input.privateBody,
                privatePreparationBodyByteLength,
                'privateBody',
            ),
        );
        return this.durableState.exclusive(async () => {
            const actionRecord = await this.durableState.readProtected(
                'actions',
                actionIdentifier(this.configuration, action),
            );
            if (actionRecord === undefined) {
                throw new DurableStateError(
                    'StateLost',
                    'Action keys are absent for private preparation consumption.',
                );
            }
            const loadedAction = await this.loadActionState(
                action,
                actionRecord,
            );
            try {
                this.verifyRosterBoundAction(
                    action,
                    loadedAction.state,
                    canonicalRosterBytes,
                );
                const carrier =
                    this.preparationParentRuntime.verifyPrivateCarrier(
                        {
                            participantCount: completionProfileParticipantCount,
                            actionProposalIdentity:
                                action.actionProposalIdentity,
                            rosterIdentity: loadedAction.state.rosterIdentity,
                            preparationAttempt,
                            predecessorIdentity: action.predecessorIdentity,
                            recipientPosition: action.participantPosition,
                        },
                        canonicalRosterBytes,
                        parentBody,
                        parentSignature,
                        privateBody,
                    );
                const senderPosition = carrier.senderPosition;
                const slotIdentifier = privatePreparationSlotIdentifier(
                    this.configuration,
                    action,
                    senderPosition,
                );
                const existing = await this.durableState.readProtected(
                    'slots',
                    slotIdentifier,
                );
                if (existing !== undefined) {
                    const loadedSlot = await this.loadPrivatePreparationSlot(
                        action,
                        loadedAction.state.rosterIdentity,
                        senderPosition,
                        existing,
                    );
                    try {
                        this.assertSlotMatchesCarrier(
                            loadedSlot.state,
                            preparationAttempt,
                            carrier.parentIdentity,
                            carrier.bodyIdentity,
                        );
                        if (
                            loadedSlot.state.phase ===
                            resolvedPrivatePreparationPhase
                        ) {
                            return {
                                senderPosition,
                                status: 'already-resolved',
                            };
                        }
                        if (
                            loadedSlot.state.phase ===
                            burnedPrivatePreparationPhase
                        ) {
                            return { senderPosition, status: 'burned' };
                        }
                        await this.burnPrivatePreparationSlot(
                            action,
                            loadedAction.rootKey,
                            loadedAction.state.rosterIdentity,
                            loadedSlot,
                        );
                        return { senderPosition, status: 'burned' };
                    } finally {
                        zeroPrivatePreparationSlotState(loadedSlot.state);
                    }
                }

                const consumedState: PrivatePreparationSlotState = {
                    phase: consumedPrivatePreparationPhase,
                    generation: 1n,
                    preparationAttempt,
                    senderPosition,
                    parentIdentity: Uint8Array.from(carrier.parentIdentity),
                    bodyIdentity: Uint8Array.from(carrier.bodyIdentity),
                    verifiedPlaintextIdentity: new Uint8Array(
                        identityByteLength,
                    ),
                    plaintext: new Uint8Array(preparationPlaintextByteLength),
                };
                const consumedPlaintext =
                    encodePrivatePreparationSlotState(consumedState);
                const consumedContext = encodeLocalRecordContext(
                    privatePreparationSlotLocalContext(
                        this.configuration,
                        action,
                        loadedAction.state.rosterIdentity,
                        consumedState.generation,
                        senderPosition,
                    ),
                );
                let consumedRecord: ProtectedRecord;
                try {
                    consumedRecord = await createProtectedRecord(
                        slotIdentifier,
                        consumedContext,
                        consumedPlaintext,
                        loadedAction.rootKey,
                    );
                } finally {
                    consumedPlaintext.fill(0);
                    consumedContext.fill(0);
                }
                await this.durableState.putIfAbsent('slots', consumedRecord);
                const retainedRecord = await this.durableState.readProtected(
                    'slots',
                    slotIdentifier,
                );
                if (retainedRecord === undefined) {
                    throw new DurableStateError(
                        'StateLost',
                        'The consumed private-preparation slot disappeared after persistence.',
                    );
                }
                const retainedSlot = await this.loadPrivatePreparationSlot(
                    action,
                    loadedAction.state.rosterIdentity,
                    senderPosition,
                    retainedRecord,
                );
                try {
                    this.assertSlotMatchesCarrier(
                        retainedSlot.state,
                        preparationAttempt,
                        carrier.parentIdentity,
                        carrier.bodyIdentity,
                    );
                    await this.configuration.afterDurableConsume?.();
                    return await this.openConsumedPrivatePreparation(
                        action,
                        canonicalRosterBytes,
                        parentBody,
                        privateBody,
                        loadedAction,
                        retainedSlot,
                    );
                } finally {
                    zeroPrivatePreparationSlotState(retainedSlot.state);
                }
            } finally {
                zeroActionState(loadedAction.state);
                parentBody.fill(0);
                parentSignature.fill(0);
                privateBody.fill(0);
            }
        });
    }

    async createSourcePackage(
        input: PrivatePreparationActionContext & {
            canonicalRosterBytes: Uint8Array;
            preparationAttempt: number;
            preparationParents: readonly PreparationParentCarrier[];
            choice: SourcePublicationChoice;
        },
    ): Promise<PublishedSourcePackage> {
        const action = copyActionContext(input);
        const canonicalRosterBytes = copyCanonicalRosterBytes(
            input.canonicalRosterBytes,
        );
        const preparationAttempt = requireUnsigned16(
            input.preparationAttempt,
            'preparationAttempt',
        );
        const preparationParents = copyPreparationParents(
            input.preparationParents,
        );
        const choice = copySourcePublicationChoice(input.choice);
        return this.durableState.exclusive(async () => {
            const actionRecord = await this.durableState.readProtected(
                'actions',
                actionIdentifier(this.configuration, action),
            );
            if (actionRecord === undefined) {
                throw new DurableStateError(
                    'StateLost',
                    'Action keys are absent for source publication.',
                );
            }
            const loadedAction = await this.loadActionState(
                action,
                actionRecord,
            );
            try {
                this.verifyRosterBoundAction(
                    action,
                    loadedAction.state,
                    canonicalRosterBytes,
                );
                const verifiedPreparation =
                    await this.verifyCompletePreparationForSource(
                        action,
                        canonicalRosterBytes,
                        preparationAttempt,
                        preparationParents,
                        loadedAction,
                    );
                try {
                    const identifier = sourceIdentifier(
                        this.configuration,
                        action,
                    );
                    const existing = await this.durableState.readProtected(
                        'sources',
                        identifier,
                    );
                    const boundSourceIdentity =
                        loadedAction.state.signatureBodyIdentities[1];
                    if (boundSourceIdentity === undefined) {
                        throw new DurableStateError(
                            'CorruptState',
                            'The source-signature slot is absent.',
                        );
                    }
                    if (existing !== undefined) {
                        if (isZero(boundSourceIdentity)) {
                            throw new DurableStateError(
                                'StateLost',
                                'Retained source state exists without its action-level signature binding.',
                            );
                        }
                        const loadedSource = await this.loadSourceState(
                            action,
                            loadedAction.state.rosterIdentity,
                            existing,
                        );
                        try {
                            const expectedScoreEncodings =
                                choice.declaration === 'submit'
                                    ? choice.scoreEncodings
                                    : new Uint8Array(sourceScoreEncodingCount);
                            if (
                                loadedSource.state.preparationAttempt !==
                                    preparationAttempt ||
                                loadedSource.state.declaration !==
                                    choice.declaration ||
                                !bytesEqual(
                                    loadedSource.state.scoreEncodings,
                                    expectedScoreEncodings,
                                ) ||
                                !bytesEqual(
                                    loadedSource.state.sourceBodyIdentity,
                                    boundSourceIdentity,
                                ) ||
                                !bytesEqual(
                                    loadedSource.state.verifiedPreparationRoot,
                                    verifiedPreparation.root,
                                ) ||
                                !bytesEqual(
                                    loadedSource.state.heldSubsetKeys,
                                    verifiedPreparation.heldSubsetKeys,
                                )
                            ) {
                                throw new DurableStateError(
                                    'Conflict',
                                    'The action is already bound to another source choice or preparation.',
                                );
                            }
                            this.validateSourceState(
                                action,
                                canonicalRosterBytes,
                                loadedAction.state,
                                loadedSource.state,
                            );
                            if (
                                loadedSource.state.phase ===
                                publishedSourcePhase
                            ) {
                                return copyPublishedSourcePackage(
                                    loadedSource.state,
                                );
                            }
                            return await this.publishRetainedSource(
                                action,
                                canonicalRosterBytes,
                                loadedAction,
                                loadedSource,
                            );
                        } finally {
                            zeroSourceState(loadedSource.state);
                        }
                    }
                    if (!isZero(boundSourceIdentity)) {
                        throw new DurableStateError(
                            'StateLost',
                            'The source-signature slot is consumed but its retained source is absent.',
                        );
                    }
                    return await this.createAndPublishSource(
                        action,
                        canonicalRosterBytes,
                        preparationAttempt,
                        choice,
                        verifiedPreparation,
                        loadedAction,
                    );
                } finally {
                    verifiedPreparation.heldSubsetKeys.fill(0);
                }
            } finally {
                zeroActionState(loadedAction.state);
            }
        });
    }

    async createFinalitySignature(
        input: PrivatePreparationActionContext & {
            canonicalRosterBytes: Uint8Array;
            preparationAttempt: number;
            sources: readonly SourceCarrier[];
            topCount: number;
        },
    ): Promise<PublishedFinalityPackage> {
        const action = copyActionContext(input);
        const canonicalRosterBytes = copyCanonicalRosterBytes(
            input.canonicalRosterBytes,
        );
        const preparationAttempt = requireUnsigned16(
            input.preparationAttempt,
            'preparationAttempt',
        );
        const sources = copySourceCarriers(input.sources);
        const topCount = requireUnsigned16(input.topCount, 'topCount');
        if (topCount < 1 || topCount > completionProfileParticipantCount) {
            throw new TypeError('topCount is outside the completion profile.');
        }
        return this.durableState.exclusive(async () => {
            const actionRecord = await this.durableState.readProtected(
                'actions',
                actionIdentifier(this.configuration, action),
            );
            const sourceRecord = await this.durableState.readProtected(
                'sources',
                sourceIdentifier(this.configuration, action),
            );
            if (actionRecord === undefined || sourceRecord === undefined) {
                throw new DurableStateError(
                    'StateLost',
                    'Published local source state is absent for finality.',
                );
            }
            const loadedAction = await this.loadActionState(
                action,
                actionRecord,
            );
            const loadedSource = await this.loadSourceState(
                action,
                loadedAction.state.rosterIdentity,
                sourceRecord,
            );
            try {
                this.verifyRosterBoundAction(
                    action,
                    loadedAction.state,
                    canonicalRosterBytes,
                );
                this.validateSourceState(
                    action,
                    canonicalRosterBytes,
                    loadedAction.state,
                    loadedSource.state,
                );
                if (
                    loadedSource.state.phase !== publishedSourcePhase ||
                    loadedSource.state.preparationAttempt !== preparationAttempt
                ) {
                    throw new DurableStateError(
                        'Conflict',
                        'The retained source is not the finalized preparation attempt.',
                    );
                }
                const verified = this.deriveVerifiedTallyContext(
                    action,
                    canonicalRosterBytes,
                    preparationAttempt,
                    sources,
                    topCount,
                    loadedAction.state,
                    loadedSource.state,
                );
                try {
                    const identifier = finalityIdentifier(
                        this.configuration,
                        action,
                    );
                    const existing = await this.durableState.readProtected(
                        'finalities',
                        identifier,
                    );
                    const boundIdentity =
                        loadedAction.state.signatureBodyIdentities[2];
                    if (boundIdentity === undefined) {
                        throw new DurableStateError(
                            'CorruptState',
                            'The finality-signature slot is absent.',
                        );
                    }
                    if (existing !== undefined) {
                        if (isZero(boundIdentity)) {
                            throw new DurableStateError(
                                'StateLost',
                                'Retained finality exists without its action-level binding.',
                            );
                        }
                        const loadedFinality = await this.loadFinalityState(
                            action,
                            loadedAction.state.rosterIdentity,
                            existing,
                        );
                        try {
                            this.validateFinalityState(
                                action,
                                canonicalRosterBytes,
                                loadedAction.state,
                                loadedFinality.state,
                                verified,
                            );
                            if (
                                !bytesEqual(
                                    boundIdentity,
                                    verified.targetIdentity,
                                )
                            ) {
                                throw new DurableStateError(
                                    'Conflict',
                                    'The action is already locked to another finality target.',
                                );
                            }
                            if (
                                loadedFinality.state.phase ===
                                publishedFinalityPhase
                            ) {
                                return copyPublishedFinalityPackage(
                                    loadedFinality.state,
                                );
                            }
                            return await this.publishRetainedFinality(
                                action,
                                canonicalRosterBytes,
                                loadedAction,
                                loadedFinality,
                                verified,
                            );
                        } finally {
                            zeroFinalityState(loadedFinality.state);
                        }
                    }
                    if (!isZero(boundIdentity)) {
                        throw new DurableStateError(
                            'StateLost',
                            'The finality-signature slot is consumed but retained finality is absent.',
                        );
                    }
                    return await this.createAndPublishFinality(
                        action,
                        canonicalRosterBytes,
                        preparationAttempt,
                        loadedAction,
                        verified,
                    );
                } finally {
                    zeroVerifiedTallyContext(verified);
                }
            } finally {
                zeroSourceState(loadedSource.state);
                zeroActionState(loadedAction.state);
            }
        });
    }

    private async createAndPublishFinality(
        action: PrivatePreparationActionContext,
        canonicalRosterBytes: Uint8Array,
        preparationAttempt: number,
        loadedAction: LoadedActionState,
        verified: VerifiedTallyContext,
    ): Promise<PublishedFinalityPackage> {
        const state: FinalityState = {
            phase: unsignedFinalityPhase,
            generation: 1n,
            preparationAttempt,
            verifiedPreparationRoot: Uint8Array.from(
                verified.verifiedPreparationRoot,
            ),
            targetBody: Uint8Array.from(verified.targetBody),
            targetIdentity: Uint8Array.from(verified.targetIdentity),
            sourceBodyIdentities: Uint8Array.from(
                verified.sourceBodyIdentities,
            ),
            sourceSubmissionBitmap: verified.sourceSubmissionBitmap,
            topCount: verified.topCount,
            targetKind: verified.targetKind,
            finalitySignature: new Uint8Array(actionSignatureCarrierByteLength),
        };
        try {
            const finalityPlaintext = encodeFinalityState(state);
            const finalityContext = encodeLocalRecordContext(
                terminalLocalContext(
                    this.configuration,
                    action,
                    loadedAction.state.rosterIdentity,
                    state.generation,
                    finalityStateKind,
                ),
            );
            let finalityRecord: ProtectedRecord;
            try {
                finalityRecord = await createProtectedRecord(
                    finalityIdentifier(this.configuration, action),
                    finalityContext,
                    finalityPlaintext,
                    loadedAction.rootKey,
                );
            } finally {
                finalityPlaintext.fill(0);
                finalityContext.fill(0);
            }
            const replacementActionState: ActionState = {
                ...loadedAction.state,
                generation: loadedAction.state.generation + 1n,
                signatureBodyIdentities:
                    loadedAction.state.signatureBodyIdentities.map(
                        (identity, index) =>
                            index === 2
                                ? Uint8Array.from(state.targetIdentity)
                                : Uint8Array.from(identity),
                    ),
            };
            const actionPlaintext = encodeActionState(replacementActionState);
            const actionContext = encodeLocalRecordContext(
                actionLocalContext(
                    this.configuration,
                    action,
                    replacementActionState.rosterIdentity,
                    replacementActionState.generation,
                ),
            );
            let actionRecord: ProtectedRecord;
            try {
                actionRecord = await createProtectedRecord(
                    actionIdentifier(this.configuration, action),
                    actionContext,
                    actionPlaintext,
                    loadedAction.rootKey,
                );
            } finally {
                actionPlaintext.fill(0);
                actionContext.fill(0);
            }
            await this.durableState.replaceExactAndPutIfAbsent(
                'actions',
                loadedAction.record,
                actionRecord,
                'finalities',
                finalityRecord,
            );
            const [retainedActionRecord, retainedFinalityRecord] =
                await Promise.all([
                    this.durableState.readProtected(
                        'actions',
                        actionIdentifier(this.configuration, action),
                    ),
                    this.durableState.readProtected(
                        'finalities',
                        finalityIdentifier(this.configuration, action),
                    ),
                ]);
            if (
                retainedActionRecord === undefined ||
                retainedFinalityRecord === undefined
            ) {
                throw new DurableStateError(
                    'StateLost',
                    'The atomic finality binding disappeared after persistence.',
                );
            }
            const reboundAction = await this.loadActionState(
                action,
                retainedActionRecord,
            );
            const retainedFinality = await this.loadFinalityState(
                action,
                reboundAction.state.rosterIdentity,
                retainedFinalityRecord,
            );
            try {
                return await this.publishRetainedFinality(
                    action,
                    canonicalRosterBytes,
                    reboundAction,
                    retainedFinality,
                    verified,
                );
            } finally {
                zeroActionState(reboundAction.state);
                zeroFinalityState(retainedFinality.state);
            }
        } finally {
            zeroFinalityState(state);
        }
    }

    private async publishRetainedFinality(
        action: PrivatePreparationActionContext,
        canonicalRosterBytes: Uint8Array,
        loadedAction: LoadedActionState,
        loadedFinality: LoadedFinalityState,
        verified: VerifiedTallyContext,
    ): Promise<PublishedFinalityPackage> {
        if (loadedFinality.state.phase !== unsignedFinalityPhase) {
            throw new DurableStateError(
                'Conflict',
                'The retained finality target is already published.',
            );
        }
        this.validateFinalityState(
            action,
            canonicalRosterBytes,
            loadedAction.state,
            loadedFinality.state,
            verified,
        );
        const signingRandomness = randomBytes(
            actionSignatureSigningRandomnessByteLength,
        );
        const signature = this.actionSignatureRuntime.signBodyIdentity(
            loadedAction.state.signingSecretKey,
            action.participantPosition,
            'finality',
            loadedFinality.state.targetIdentity,
            signingRandomness,
        );
        let signatureCarrier: Uint8Array;
        try {
            signatureCarrier = this.finalityRuntime.encodeSignature(
                action.participantPosition,
                loadedFinality.state.targetIdentity,
                signature,
            );
        } finally {
            signature.fill(0);
            signingRandomness.fill(0);
        }
        const replacementState: FinalityState = {
            ...loadedFinality.state,
            phase: publishedFinalityPhase,
            generation: loadedFinality.state.generation + 1n,
            finalitySignature: signatureCarrier,
        };
        await this.replaceFinalityState(
            action,
            loadedAction,
            loadedFinality,
            replacementState,
        );
        const retained = await this.durableState.readProtected(
            'finalities',
            loadedFinality.record.id,
        );
        if (retained === undefined) {
            throw new DurableStateError(
                'StateLost',
                'The published finality state disappeared after persistence.',
            );
        }
        const reloaded = await this.loadFinalityState(
            action,
            loadedAction.state.rosterIdentity,
            retained,
        );
        try {
            this.validateFinalityState(
                action,
                canonicalRosterBytes,
                loadedAction.state,
                reloaded.state,
                verified,
            );
            return copyPublishedFinalityPackage(reloaded.state);
        } finally {
            zeroFinalityState(reloaded.state);
        }
    }

    async finalizeNoResult(
        input: PrivatePreparationActionContext & {
            canonicalRosterBytes: Uint8Array;
            preparationAttempt: number;
            sources: readonly SourceCarrier[];
            finalitySignatures: readonly FinalitySignatureCarrier[];
            topCount: number;
        },
    ): Promise<TallyEvaluationProgress> {
        const action = copyActionContext(input);
        const canonicalRosterBytes = copyCanonicalRosterBytes(
            input.canonicalRosterBytes,
        );
        const preparationAttempt = requireUnsigned16(
            input.preparationAttempt,
            'preparationAttempt',
        );
        const sources = copySourceCarriers(input.sources);
        const finalitySignatures = copyFinalitySignatures(
            input.finalitySignatures,
        );
        const topCount = requireUnsigned16(input.topCount, 'topCount');
        if (topCount < 1 || topCount > completionProfileParticipantCount) {
            throw new TypeError('topCount is outside the completion profile.');
        }
        return this.durableState.exclusive(async () => {
            const actionRecord = await this.durableState.readProtected(
                'actions',
                actionIdentifier(this.configuration, action),
            );
            const sourceRecord = await this.durableState.readProtected(
                'sources',
                sourceIdentifier(this.configuration, action),
            );
            if (actionRecord === undefined || sourceRecord === undefined) {
                throw new DurableStateError(
                    'StateLost',
                    'Published local source state is absent for no-result finalization.',
                );
            }
            const loadedAction = await this.loadActionState(
                action,
                actionRecord,
            );
            const loadedSource = await this.loadSourceState(
                action,
                loadedAction.state.rosterIdentity,
                sourceRecord,
            );
            try {
                this.verifyRosterBoundAction(
                    action,
                    loadedAction.state,
                    canonicalRosterBytes,
                );
                this.validateSourceState(
                    action,
                    canonicalRosterBytes,
                    loadedAction.state,
                    loadedSource.state,
                );
                if (
                    loadedSource.state.phase !== publishedSourcePhase ||
                    loadedSource.state.preparationAttempt !== preparationAttempt
                ) {
                    throw new DurableStateError(
                        'Conflict',
                        'The retained source is not the finalized preparation attempt.',
                    );
                }
                const verified = this.deriveVerifiedTallyContext(
                    action,
                    canonicalRosterBytes,
                    preparationAttempt,
                    sources,
                    topCount,
                    loadedAction.state,
                    loadedSource.state,
                );
                try {
                    this.verifyNoResultCertificate(
                        verified,
                        canonicalRosterBytes,
                        finalitySignatures,
                    );
                    const identifier = noResultIdentifier(
                        this.configuration,
                        action,
                    );
                    const existing = await this.durableState.readProtected(
                        'evaluations',
                        identifier,
                    );
                    if (existing !== undefined) {
                        const loadedNoResult = await this.loadNoResultState(
                            action,
                            loadedAction.state.rosterIdentity,
                            existing,
                        );
                        try {
                            this.validateFinalizedNoResultState(
                                loadedNoResult.state,
                                verified,
                            );
                            return copyTallyEvaluationProgress(
                                loadedNoResult.state,
                                this.constructionKernelRuntime.measureResources(),
                            );
                        } finally {
                            zeroNoResultState(loadedNoResult.state);
                        }
                    }
                    const state: NoResultState = {
                        generation: 1n,
                        targetIdentity: Uint8Array.from(
                            verified.targetIdentity,
                        ),
                        topCount: verified.topCount,
                        sourceSubmissionBitmap: verified.sourceSubmissionBitmap,
                        acceptedBallotAuthorshipBitmap: 0,
                    };
                    try {
                        this.validateFinalizedNoResultState(state, verified);
                        await this.insertNoResultState(
                            action,
                            loadedAction,
                            state,
                        );
                    } finally {
                        zeroNoResultState(state);
                    }
                    const retained = await this.durableState.readProtected(
                        'evaluations',
                        identifier,
                    );
                    if (retained === undefined) {
                        throw new DurableStateError(
                            'StateLost',
                            'The durable no-result terminal disappeared after persistence.',
                        );
                    }
                    const reloaded = await this.loadNoResultState(
                        action,
                        loadedAction.state.rosterIdentity,
                        retained,
                    );
                    try {
                        this.validateFinalizedNoResultState(
                            reloaded.state,
                            verified,
                        );
                        return copyTallyEvaluationProgress(
                            reloaded.state,
                            this.constructionKernelRuntime.measureResources(),
                        );
                    } finally {
                        zeroNoResultState(reloaded.state);
                    }
                } finally {
                    zeroVerifiedTallyContext(verified);
                }
            } finally {
                zeroSourceState(loadedSource.state);
                zeroActionState(loadedAction.state);
            }
        });
    }

    async readTallyResult(
        input: PrivatePreparationActionContext,
    ): Promise<TallyEvaluationProgress> {
        const action = copyActionContext(input);
        return this.durableState.exclusive(async () => {
            const actionRecord = await this.durableState.readProtected(
                'actions',
                actionIdentifier(this.configuration, action),
            );
            if (actionRecord === undefined) {
                throw new DurableStateError(
                    'StateLost',
                    'Action state is absent for tally result retrieval.',
                );
            }
            const loadedAction = await this.loadActionState(
                action,
                actionRecord,
            );
            try {
                const noResultRecord = await this.durableState.readProtected(
                    'evaluations',
                    noResultIdentifier(this.configuration, action),
                );
                if (noResultRecord !== undefined) {
                    const loadedNoResult = await this.loadNoResultState(
                        action,
                        loadedAction.state.rosterIdentity,
                        noResultRecord,
                    );
                    try {
                        return copyTallyEvaluationProgress(
                            loadedNoResult.state,
                            this.constructionKernelRuntime.measureResources(),
                        );
                    } finally {
                        zeroNoResultState(loadedNoResult.state);
                    }
                }
                throw new DurableStateError(
                    'StateLost',
                    'No certificate-verified durable no-result terminal is available.',
                );
            } finally {
                zeroActionState(loadedAction.state);
            }
        });
    }

    private deriveVerifiedTallyContext(
        action: PrivatePreparationActionContext,
        canonicalRosterBytes: Uint8Array,
        preparationAttempt: number,
        sources: readonly SourceCarrier[],
        topCount: number,
        actionState: ActionState,
        sourceState: SourceState,
    ): VerifiedTallyContext {
        const derivationContext = {
            participantCount: completionProfileParticipantCount,
            runtimeIdentity: this.configuration.runtimeIdentity,
            candidateBuildIdentity: this.configuration.candidateBuildIdentity,
            actionProposalIdentity: action.actionProposalIdentity,
            actionDefinitionIdentity: action.actionDefinitionIdentity,
            rosterIdentity: actionState.rosterIdentity,
            preparationAttempt,
            predecessorIdentity: action.predecessorIdentity,
            verifiedPreparationRoot: sourceState.verifiedPreparationRoot,
            topCount,
        };
        const localSource = sources[action.participantPosition];
        if (
            localSource === undefined ||
            !bytesEqual(localSource.body, sourceState.sourceBody) ||
            !bytesEqual(localSource.signature, sourceState.sourceSignature)
        ) {
            throw new DurableStateError(
                'Conflict',
                'The finalized source inventory does not contain the retained local source.',
            );
        }
        const target = this.finalityRuntime.deriveTarget(
            derivationContext,
            canonicalRosterBytes,
            sources,
        );
        return {
            verifiedPreparationRoot: Uint8Array.from(
                sourceState.verifiedPreparationRoot,
            ),
            targetBody: target.targetBody,
            targetIdentity: target.targetIdentity,
            sourceBodyIdentities: target.sourceBodyIdentities,
            sourceSubmissionBitmap: target.sourceSubmissionBitmap,
            topCount: target.topCount,
            targetKind: target.targetKind,
        };
    }

    private verifyNoResultCertificate(
        verified: VerifiedTallyContext,
        canonicalRosterBytes: Uint8Array,
        finalitySignatures: readonly FinalitySignatureCarrier[],
    ): void {
        const certificate = this.finalityRuntime.verifyCertificate(
            verified.targetBody,
            canonicalRosterBytes,
            finalitySignatures,
        );
        if (
            verified.targetKind !== 'no-result' ||
            certificate.targetKind !== 'no-result' ||
            verified.sourceSubmissionBitmap !== 0 ||
            certificate.sourceSubmissionBitmap !== 0 ||
            certificate.topCount !== verified.topCount ||
            !bytesEqual(certificate.targetIdentity, verified.targetIdentity)
        ) {
            throw new Error(
                'No-result finalization requires the exact finalized empty source inventory.',
            );
        }
    }

    private validateFinalityState(
        action: PrivatePreparationActionContext,
        canonicalRosterBytes: Uint8Array,
        actionState: ActionState,
        state: FinalityState,
        verified: VerifiedTallyContext,
    ): void {
        const boundIdentity = actionState.signatureBodyIdentities[2];
        if (
            state.generation < 1n ||
            state.verifiedPreparationRoot.byteLength !== identityByteLength ||
            state.targetBody.byteLength !== finalityTargetBodyByteLength ||
            state.targetIdentity.byteLength !== identityByteLength ||
            state.sourceBodyIdentities.byteLength !==
                sourceBodyIdentityVectorByteLength ||
            state.finalitySignature.byteLength !==
                actionSignatureCarrierByteLength ||
            state.sourceSubmissionBitmap >=
                1 << completionProfileParticipantCount ||
            state.topCount !== verified.topCount ||
            boundIdentity === undefined ||
            !bytesEqual(boundIdentity, state.targetIdentity) ||
            !bytesEqual(
                state.verifiedPreparationRoot,
                verified.verifiedPreparationRoot,
            ) ||
            !bytesEqual(state.targetBody, verified.targetBody) ||
            !bytesEqual(state.targetIdentity, verified.targetIdentity) ||
            !bytesEqual(
                state.sourceBodyIdentities,
                verified.sourceBodyIdentities,
            ) ||
            state.sourceSubmissionBitmap !== verified.sourceSubmissionBitmap ||
            state.targetKind !== verified.targetKind
        ) {
            throw new DurableStateError(
                'Conflict',
                'The retained finality state does not match the verified source inventory.',
            );
        }
        if (state.phase === unsignedFinalityPhase) {
            if (!isZero(state.finalitySignature)) {
                throw new DurableStateError(
                    'CorruptState',
                    'Unsigned retained finality contains a signature.',
                );
            }
            return;
        }
        this.finalityRuntime.verifySignature(
            action.participantPosition,
            state.targetBody,
            canonicalRosterBytes,
            state.finalitySignature,
        );
    }

    private validateFinalizedNoResultState(
        state: NoResultState,
        verified: VerifiedTallyContext,
    ): void {
        if (
            verified.targetKind !== 'no-result' ||
            verified.sourceSubmissionBitmap !== 0 ||
            state.generation < 1n ||
            state.targetIdentity.byteLength !== identityByteLength ||
            !bytesEqual(state.targetIdentity, verified.targetIdentity) ||
            state.topCount !== verified.topCount ||
            state.sourceSubmissionBitmap !== 0 ||
            state.acceptedBallotAuthorshipBitmap !== 0
        ) {
            throw new DurableStateError(
                'CorruptState',
                'The retained finalized no-result state is inconsistent.',
            );
        }
    }

    private async replaceFinalityState(
        action: PrivatePreparationActionContext,
        loadedAction: LoadedActionState,
        loadedFinality: LoadedFinalityState,
        replacementState: FinalityState,
    ): Promise<void> {
        const plaintext = encodeFinalityState(replacementState);
        const context = encodeLocalRecordContext(
            terminalLocalContext(
                this.configuration,
                action,
                loadedAction.state.rosterIdentity,
                replacementState.generation,
                finalityStateKind,
            ),
        );
        let replacement: ProtectedRecord;
        try {
            replacement = await createProtectedRecord(
                loadedFinality.record.id,
                context,
                plaintext,
                loadedAction.rootKey,
            );
        } finally {
            plaintext.fill(0);
            context.fill(0);
        }
        await this.durableState.replaceExact(
            'finalities',
            loadedFinality.record,
            replacement,
        );
    }

    private async insertNoResultState(
        action: PrivatePreparationActionContext,
        loadedAction: LoadedActionState,
        state: NoResultState,
    ): Promise<void> {
        const plaintext = encodeNoResultState(state);
        const context = encodeLocalRecordContext(
            terminalLocalContext(
                this.configuration,
                action,
                loadedAction.state.rosterIdentity,
                state.generation,
                noResultStateKind,
            ),
        );
        let record: ProtectedRecord;
        try {
            record = await createProtectedRecord(
                noResultIdentifier(this.configuration, action),
                context,
                plaintext,
                loadedAction.rootKey,
            );
        } finally {
            plaintext.fill(0);
            context.fill(0);
        }
        await this.durableState.putIfAbsent('evaluations', record);
    }

    private async verifyCompletePreparationForSource(
        action: PrivatePreparationActionContext,
        canonicalRosterBytes: Uint8Array,
        preparationAttempt: number,
        preparationParents: readonly PreparationParentCarrier[],
        loadedAction: LoadedActionState,
    ): Promise<VerifiedCompletePreparation> {
        const preparationRecord = await this.durableState.readProtected(
            'preparations',
            preparationIdentifier(this.configuration, action),
        );
        if (preparationRecord === undefined) {
            throw new Error(
                'The local preparation package is unavailable for source publication.',
            );
        }
        const loadedPreparation = await this.loadPreparationState(
            action,
            loadedAction.state.rosterIdentity,
            preparationRecord,
        );
        const loadedSlots: LoadedPrivatePreparationSlotState[] = [];
        const remotePlaintexts: Uint8Array[] = [];
        try {
            if (
                loadedPreparation.state.phase !== publishedPreparationPhase ||
                loadedPreparation.state.preparationAttempt !==
                    preparationAttempt
            ) {
                throw new Error(
                    'The local preparation is not the required published attempt.',
                );
            }
            this.validatePreparationState(
                action,
                canonicalRosterBytes,
                loadedAction.state,
                loadedPreparation.state,
            );
            const expectedParentIdentities: Uint8Array[] = Array.from(
                { length: completionProfileParticipantCount },
                () => new Uint8Array(identityByteLength),
            );
            expectedParentIdentities[action.participantPosition] =
                Uint8Array.from(loadedPreparation.state.parentIdentity);
            for (const senderPosition of remotePositions(
                action.participantPosition,
            )) {
                const slotRecord = await this.durableState.readProtected(
                    'slots',
                    privatePreparationSlotIdentifier(
                        this.configuration,
                        action,
                        senderPosition,
                    ),
                );
                if (slotRecord === undefined) {
                    throw new Error(
                        'A required private preparation delivery has not been consumed.',
                    );
                }
                const loadedSlot = await this.loadPrivatePreparationSlot(
                    action,
                    loadedAction.state.rosterIdentity,
                    senderPosition,
                    slotRecord,
                );
                loadedSlots.push(loadedSlot);
                if (
                    loadedSlot.state.phase !==
                        resolvedPrivatePreparationPhase ||
                    loadedSlot.state.preparationAttempt !== preparationAttempt
                ) {
                    throw new Error(
                        'A required private preparation delivery is not positively resolved.',
                    );
                }
                expectedParentIdentities[senderPosition] = Uint8Array.from(
                    loadedSlot.state.parentIdentity,
                );
                remotePlaintexts.push(
                    Uint8Array.from(loadedSlot.state.plaintext),
                );
            }
            const verified = this.sourceRuntime.verifyCompletePreparation(
                {
                    participantCount: completionProfileParticipantCount,
                    actionProposalIdentity: action.actionProposalIdentity,
                    rosterIdentity: loadedAction.state.rosterIdentity,
                    preparationAttempt,
                    predecessorIdentity: action.predecessorIdentity,
                },
                action.participantPosition,
                canonicalRosterBytes,
                preparationParents,
                loadedPreparation.state.contributionOpenings,
                loadedPreparation.state.pairwiseMasters,
                remotePlaintexts,
            );
            for (
                let position = 0;
                position < completionProfileParticipantCount;
                position += 1
            ) {
                const expectedIdentity = expectedParentIdentities[position];
                const verifiedIdentity = verified.parentIdentities.subarray(
                    position * identityByteLength,
                    (position + 1) * identityByteLength,
                );
                if (
                    expectedIdentity === undefined ||
                    !bytesEqual(expectedIdentity, verifiedIdentity)
                ) {
                    verified.heldSubsetKeys.fill(0);
                    throw new DurableStateError(
                        'Conflict',
                        'The certified preparation parent does not match the retained private delivery.',
                    );
                }
            }
            return verified;
        } finally {
            zeroPreparationState(loadedPreparation.state);
            for (const loadedSlot of loadedSlots) {
                zeroPrivatePreparationSlotState(loadedSlot.state);
            }
            for (const plaintext of remotePlaintexts) {
                plaintext.fill(0);
            }
        }
    }

    private async createAndPublishSource(
        action: PrivatePreparationActionContext,
        canonicalRosterBytes: Uint8Array,
        preparationAttempt: number,
        choice: SourcePublicationChoice,
        verifiedPreparation: VerifiedCompletePreparation,
        loadedAction: LoadedActionState,
    ): Promise<PublishedSourcePackage> {
        const declaration = choice.declaration;
        const scoreEncodings =
            declaration === 'submit'
                ? Uint8Array.from(choice.scoreEncodings)
                : new Uint8Array(sourceScoreEncodingCount);
        const sourceProtocolContext = {
            participantCount: completionProfileParticipantCount,
            actionProposalIdentity: action.actionProposalIdentity,
            rosterIdentity: loadedAction.state.rosterIdentity,
            preparationAttempt,
            predecessorIdentity: action.predecessorIdentity,
            verifiedPreparationRoot: verifiedPreparation.root,
            senderPosition: action.participantPosition,
        } as const;
        const correction =
            declaration === 'submit'
                ? this.sourceRuntime.deriveHonestCorrection(
                      sourceProtocolContext,
                      scoreEncodings,
                      verifiedPreparation.heldSubsetKeys,
                  )
                : undefined;
        const encodedSource = this.sourceRuntime.encodeBody(
            sourceProtocolContext,
            declaration,
            correction,
        );
        const state: SourceState = {
            phase: unsignedSourcePhase,
            generation: 1n,
            preparationAttempt,
            verifiedPreparationRoot: Uint8Array.from(verifiedPreparation.root),
            declaration,
            scoreEncodings,
            sourceBody: encodedSource.body,
            sourceBodyIdentity: encodedSource.identity,
            sourceSignature: new Uint8Array(actionSignatureCarrierByteLength),
            heldSubsetKeys: Uint8Array.from(verifiedPreparation.heldSubsetKeys),
        };
        try {
            this.validateSourceState(
                action,
                canonicalRosterBytes,
                loadedAction.state,
                state,
            );
            const sourcePlaintext = encodeSourceState(state);
            const sourceContext = encodeLocalRecordContext(
                sourceLocalContext(
                    this.configuration,
                    action,
                    loadedAction.state.rosterIdentity,
                    state.generation,
                ),
            );
            let sourceRecord: ProtectedRecord;
            try {
                sourceRecord = await createProtectedRecord(
                    sourceIdentifier(this.configuration, action),
                    sourceContext,
                    sourcePlaintext,
                    loadedAction.rootKey,
                );
            } finally {
                sourcePlaintext.fill(0);
                sourceContext.fill(0);
            }
            const replacementActionState: ActionState = {
                ...loadedAction.state,
                generation: loadedAction.state.generation + 1n,
                signatureBodyIdentities:
                    loadedAction.state.signatureBodyIdentities.map(
                        (identity, index) =>
                            index === 1
                                ? Uint8Array.from(state.sourceBodyIdentity)
                                : Uint8Array.from(identity),
                    ),
            };
            const actionPlaintext = encodeActionState(replacementActionState);
            const actionContext = encodeLocalRecordContext(
                actionLocalContext(
                    this.configuration,
                    action,
                    replacementActionState.rosterIdentity,
                    replacementActionState.generation,
                ),
            );
            let actionRecord: ProtectedRecord;
            try {
                actionRecord = await createProtectedRecord(
                    actionIdentifier(this.configuration, action),
                    actionContext,
                    actionPlaintext,
                    loadedAction.rootKey,
                );
            } finally {
                actionPlaintext.fill(0);
                actionContext.fill(0);
            }
            await this.durableState.replaceExactAndPutIfAbsent(
                'actions',
                loadedAction.record,
                actionRecord,
                'sources',
                sourceRecord,
            );
            await this.configuration.afterDurableSourceBind?.();
            const [retainedActionRecord, retainedSourceRecord] =
                await Promise.all([
                    this.durableState.readProtected(
                        'actions',
                        actionIdentifier(this.configuration, action),
                    ),
                    this.durableState.readProtected(
                        'sources',
                        sourceIdentifier(this.configuration, action),
                    ),
                ]);
            if (
                retainedActionRecord === undefined ||
                retainedSourceRecord === undefined
            ) {
                throw new DurableStateError(
                    'StateLost',
                    'The atomic source binding disappeared after persistence.',
                );
            }
            const reboundAction = await this.loadActionState(
                action,
                retainedActionRecord,
            );
            const retainedSource = await this.loadSourceState(
                action,
                reboundAction.state.rosterIdentity,
                retainedSourceRecord,
            );
            try {
                if (
                    !bytesEqual(
                        reboundAction.state.signatureBodyIdentities[1] ??
                            new Uint8Array(),
                        retainedSource.state.sourceBodyIdentity,
                    )
                ) {
                    throw new DurableStateError(
                        'StateLost',
                        'The durable source binding is inconsistent.',
                    );
                }
                return await this.publishRetainedSource(
                    action,
                    canonicalRosterBytes,
                    reboundAction,
                    retainedSource,
                );
            } finally {
                zeroActionState(reboundAction.state);
                zeroSourceState(retainedSource.state);
            }
        } finally {
            zeroSourceState(state);
        }
    }

    private async publishRetainedSource(
        action: PrivatePreparationActionContext,
        canonicalRosterBytes: Uint8Array,
        loadedAction: LoadedActionState,
        loadedSource: LoadedSourceState,
    ): Promise<PublishedSourcePackage> {
        if (loadedSource.state.phase !== unsignedSourcePhase) {
            throw new DurableStateError(
                'Conflict',
                'The retained source is already published.',
            );
        }
        this.validateSourceState(
            action,
            canonicalRosterBytes,
            loadedAction.state,
            loadedSource.state,
        );
        const signingRandomness = randomBytes(
            actionSignatureSigningRandomnessByteLength,
        );
        const signature = this.actionSignatureRuntime.signBodyIdentity(
            loadedAction.state.signingSecretKey,
            action.participantPosition,
            'source',
            loadedSource.state.sourceBodyIdentity,
            signingRandomness,
        );
        let signatureCarrier: Uint8Array;
        try {
            signatureCarrier = this.sourceRuntime.encodeSignature(
                action.participantPosition,
                loadedSource.state.sourceBodyIdentity,
                signature,
            );
        } finally {
            signature.fill(0);
            signingRandomness.fill(0);
        }
        const replacementState: SourceState = {
            ...loadedSource.state,
            phase: publishedSourcePhase,
            generation: loadedSource.state.generation + 1n,
            sourceSignature: signatureCarrier,
        };
        const plaintext = encodeSourceState(replacementState);
        const context = encodeLocalRecordContext(
            sourceLocalContext(
                this.configuration,
                action,
                loadedAction.state.rosterIdentity,
                replacementState.generation,
            ),
        );
        let replacement: ProtectedRecord;
        try {
            replacement = await createProtectedRecord(
                loadedSource.record.id,
                context,
                plaintext,
                loadedAction.rootKey,
            );
        } finally {
            plaintext.fill(0);
            context.fill(0);
        }
        await this.durableState.replaceExact(
            'sources',
            loadedSource.record,
            replacement,
        );
        const retained = await this.durableState.readProtected(
            'sources',
            loadedSource.record.id,
        );
        if (retained === undefined) {
            throw new DurableStateError(
                'StateLost',
                'The published source disappeared after persistence.',
            );
        }
        const reloaded = await this.loadSourceState(
            action,
            loadedAction.state.rosterIdentity,
            retained,
        );
        try {
            this.validateSourceState(
                action,
                canonicalRosterBytes,
                loadedAction.state,
                reloaded.state,
            );
            return copyPublishedSourcePackage(reloaded.state);
        } finally {
            zeroSourceState(reloaded.state);
        }
    }

    private validateSourceState(
        action: PrivatePreparationActionContext,
        canonicalRosterBytes: Uint8Array,
        actionState: ActionState,
        state: SourceState,
    ): void {
        if (
            state.verifiedPreparationRoot.byteLength !== identityByteLength ||
            state.sourceBodyIdentity.byteLength !== identityByteLength ||
            state.sourceSignature.byteLength !==
                actionSignatureCarrierByteLength ||
            state.heldSubsetKeys.byteLength !== heldSubsetKeyVectorByteLength ||
            state.scoreEncodings.byteLength !== sourceScoreEncodingCount ||
            state.scoreEncodings.some((score) => score > 0x0f) ||
            (state.declaration === 'abstain' && !isZero(state.scoreEncodings))
        ) {
            throw new DurableStateError(
                'CorruptState',
                'The retained source state has invalid dimensions or semantics.',
            );
        }
        const sourceContext = {
            participantCount: completionProfileParticipantCount,
            actionProposalIdentity: action.actionProposalIdentity,
            rosterIdentity: actionState.rosterIdentity,
            preparationAttempt: state.preparationAttempt,
            predecessorIdentity: action.predecessorIdentity,
            verifiedPreparationRoot: state.verifiedPreparationRoot,
            senderPosition: action.participantPosition,
        } as const;
        const correction =
            state.declaration === 'submit'
                ? this.sourceRuntime.deriveHonestCorrection(
                      sourceContext,
                      state.scoreEncodings,
                      state.heldSubsetKeys,
                  )
                : undefined;
        const encoded = this.sourceRuntime.encodeBody(
            sourceContext,
            state.declaration,
            correction,
        );
        if (
            !bytesEqual(encoded.body, state.sourceBody) ||
            !bytesEqual(encoded.identity, state.sourceBodyIdentity)
        ) {
            throw new DurableStateError(
                'CorruptState',
                'The retained source body does not match its fixed private input.',
            );
        }
        const boundIdentity = actionState.signatureBodyIdentities[1];
        if (
            boundIdentity === undefined ||
            (!isZero(boundIdentity) &&
                !bytesEqual(boundIdentity, state.sourceBodyIdentity)) ||
            (state.phase === publishedSourcePhase && isZero(boundIdentity))
        ) {
            throw new DurableStateError(
                'StateLost',
                'The retained source does not match its action-level one-shot binding.',
            );
        }
        if (state.phase === unsignedSourcePhase) {
            if (!isZero(state.sourceSignature)) {
                throw new DurableStateError(
                    'CorruptState',
                    'The unsigned source contains a signature carrier.',
                );
            }
            return;
        }
        const verified = this.sourceRuntime.verify(
            sourceContext,
            state.declaration,
            canonicalRosterBytes,
            state.sourceBody,
            state.sourceSignature,
        );
        if (
            verified.senderPosition !== action.participantPosition ||
            verified.declaration !== state.declaration ||
            (correction === undefined
                ? verified.correction !== undefined
                : verified.correction === undefined ||
                  !bytesEqual(verified.correction, correction)) ||
            !bytesEqual(verified.bodyIdentity, state.sourceBodyIdentity) ||
            !bytesEqual(
                verified.verifiedPreparationRoot,
                state.verifiedPreparationRoot,
            )
        ) {
            throw new DurableStateError(
                'CorruptState',
                'The retained signed source failed semantic verification.',
            );
        }
    }

    private verifyRosterBoundAction(
        action: PrivatePreparationActionContext,
        state: ActionState,
        canonicalRosterBytes: Uint8Array = state.canonicalRosterBytes,
    ): void {
        if (state.phase !== rosterBoundActionPhase) {
            throw new DurableStateError(
                'Conflict',
                'The action is not bound to a frozen roster.',
            );
        }
        const rosterIdentity = this.rosterRuntime.verify(canonicalRosterBytes);
        if (
            action.participantPosition !== state.participantPosition ||
            !bytesEqual(canonicalRosterBytes, state.canonicalRosterBytes) ||
            !bytesEqual(rosterIdentity, state.rosterIdentity)
        ) {
            throw new DurableStateError(
                'Conflict',
                'The retained action is bound to another frozen roster.',
            );
        }
    }

    private async createAndPublishPreparation(
        action: PrivatePreparationActionContext,
        canonicalRosterBytes: Uint8Array,
        preparationAttempt: number,
        loadedAction: LoadedActionState,
    ): Promise<PublishedPreparationPackage> {
        const contributionOpenings = randomBytes(
            preparationContributionOpeningVectorByteLength,
        );
        const pairwiseMasters = randomBytes(
            preparationPairwiseMasterVectorByteLength,
        );
        const materialContext = {
            participantCount: completionProfileParticipantCount,
            actionProposalIdentity: action.actionProposalIdentity,
            rosterIdentity: loadedAction.state.rosterIdentity,
            preparationAttempt,
            predecessorIdentity: action.predecessorIdentity,
            senderPosition: action.participantPosition,
        } as const;
        const material = this.preparationMaterialRuntime.generate(
            materialContext,
            contributionOpenings,
            pairwiseMasters,
        );
        const privateBodies: Uint8Array[] = [];
        const privateBodyIdentities: Uint8Array[] = [];
        const recipients = remotePositions(action.participantPosition);
        try {
            for (const [
                recipientIndex,
                recipientPosition,
            ] of recipients.entries()) {
                const plaintext = material.recipientPlaintexts[recipientIndex];
                if (plaintext === undefined) {
                    throw new Error(
                        'Generated preparation material omitted a recipient.',
                    );
                }
                const mailboxEncapsulationKey =
                    this.rosterRuntime.resolveMailboxKey(
                        loadedAction.state.rosterIdentity,
                        action.participantPosition,
                        recipientPosition,
                        canonicalRosterBytes,
                    );
                const pairEncryptionRandomness = randomBytes(
                    pairEncryptionRandomnessByteLength,
                );
                try {
                    const sealed = this.privatePreparationBodyRuntime.seal(
                        {
                            ...materialContext,
                            recipientPosition,
                        },
                        mailboxEncapsulationKey,
                        pairEncryptionRandomness,
                        plaintext,
                    );
                    privateBodies.push(sealed.body);
                    privateBodyIdentities.push(sealed.identity);
                } finally {
                    mailboxEncapsulationKey.fill(0);
                    pairEncryptionRandomness.fill(0);
                }
            }
            const parent = this.preparationParentRuntime.encode({
                ...materialContext,
                subsetCommitments: material.subsetCommitments,
                privateBodyIdentities,
            });
            const state: PreparationState = {
                phase: unsignedPreparationPhase,
                generation: 1n,
                preparationAttempt,
                parentIdentity: parent.identity,
                parentBody: parent.body,
                parentSignature: new Uint8Array(
                    actionSignatureCarrierByteLength,
                ),
                privateBodyIdentities,
                privateBodies,
                contributionOpenings,
                pairwiseMasters,
            };
            this.validatePreparationState(
                action,
                canonicalRosterBytes,
                loadedAction.state,
                state,
            );
            const preparationPlaintext = encodePreparationState(state);
            const preparationContext = encodeLocalRecordContext(
                preparationLocalContext(
                    this.configuration,
                    action,
                    loadedAction.state.rosterIdentity,
                    state.generation,
                    preparationAttempt,
                ),
            );
            let preparationRecord: ProtectedRecord;
            try {
                preparationRecord = await createProtectedRecord(
                    preparationIdentifier(this.configuration, action),
                    preparationContext,
                    preparationPlaintext,
                    loadedAction.rootKey,
                );
            } finally {
                preparationPlaintext.fill(0);
                preparationContext.fill(0);
            }
            const replacementActionState: ActionState = {
                ...loadedAction.state,
                generation: loadedAction.state.generation + 1n,
                signatureBodyIdentities:
                    loadedAction.state.signatureBodyIdentities.map(
                        (identity, index) =>
                            index === 0
                                ? Uint8Array.from(parent.identity)
                                : Uint8Array.from(identity),
                    ),
            };
            const actionPlaintext = encodeActionState(replacementActionState);
            const actionContext = encodeLocalRecordContext(
                actionLocalContext(
                    this.configuration,
                    action,
                    replacementActionState.rosterIdentity,
                    replacementActionState.generation,
                ),
            );
            let actionRecord: ProtectedRecord;
            try {
                actionRecord = await createProtectedRecord(
                    actionIdentifier(this.configuration, action),
                    actionContext,
                    actionPlaintext,
                    loadedAction.rootKey,
                );
            } finally {
                actionPlaintext.fill(0);
                actionContext.fill(0);
            }
            await this.durableState.replaceExactAndPutIfAbsent(
                'actions',
                loadedAction.record,
                actionRecord,
                'preparations',
                preparationRecord,
            );
            const [retainedActionRecord, retainedPreparationRecord] =
                await Promise.all([
                    this.durableState.readProtected(
                        'actions',
                        actionIdentifier(this.configuration, action),
                    ),
                    this.durableState.readProtected(
                        'preparations',
                        preparationIdentifier(this.configuration, action),
                    ),
                ]);
            if (
                retainedActionRecord === undefined ||
                retainedPreparationRecord === undefined
            ) {
                throw new DurableStateError(
                    'StateLost',
                    'The atomic preparation binding disappeared after persistence.',
                );
            }
            const reboundAction = await this.loadActionState(
                action,
                retainedActionRecord,
            );
            const retainedPreparation = await this.loadPreparationState(
                action,
                reboundAction.state.rosterIdentity,
                retainedPreparationRecord,
            );
            try {
                if (
                    !bytesEqual(
                        reboundAction.state.signatureBodyIdentities[0] ??
                            new Uint8Array(),
                        retainedPreparation.state.parentIdentity,
                    )
                ) {
                    throw new DurableStateError(
                        'StateLost',
                        'The durable preparation binding is inconsistent.',
                    );
                }
                return await this.publishRetainedPreparation(
                    action,
                    canonicalRosterBytes,
                    reboundAction,
                    retainedPreparation,
                );
            } finally {
                zeroActionState(reboundAction.state);
                zeroPreparationState(retainedPreparation.state);
            }
        } finally {
            for (const plaintext of material.recipientPlaintexts) {
                plaintext.fill(0);
            }
            contributionOpenings.fill(0);
            pairwiseMasters.fill(0);
        }
    }

    private async publishRetainedPreparation(
        action: PrivatePreparationActionContext,
        canonicalRosterBytes: Uint8Array,
        loadedAction: LoadedActionState,
        loadedPreparation: LoadedPreparationState,
    ): Promise<PublishedPreparationPackage> {
        if (loadedPreparation.state.phase !== unsignedPreparationPhase) {
            throw new DurableStateError(
                'Conflict',
                'The retained preparation is already published.',
            );
        }
        this.validatePreparationState(
            action,
            canonicalRosterBytes,
            loadedAction.state,
            loadedPreparation.state,
        );
        const signingRandomness = randomBytes(
            actionSignatureSigningRandomnessByteLength,
        );
        const signature = this.actionSignatureRuntime.signBodyIdentity(
            loadedAction.state.signingSecretKey,
            action.participantPosition,
            'preparation',
            loadedPreparation.state.parentIdentity,
            signingRandomness,
        );
        let signatureCarrier: Uint8Array;
        try {
            signatureCarrier = this.preparationParentRuntime.encodeSignature(
                completionProfileParticipantCount,
                action.participantPosition,
                loadedPreparation.state.parentIdentity,
                signature,
            );
        } finally {
            signature.fill(0);
            signingRandomness.fill(0);
        }
        const replacementState: PreparationState = {
            ...loadedPreparation.state,
            phase: publishedPreparationPhase,
            generation: loadedPreparation.state.generation + 1n,
            parentSignature: signatureCarrier,
        };
        const plaintext = encodePreparationState(replacementState);
        const context = encodeLocalRecordContext(
            preparationLocalContext(
                this.configuration,
                action,
                loadedAction.state.rosterIdentity,
                replacementState.generation,
                replacementState.preparationAttempt,
            ),
        );
        let replacement: ProtectedRecord;
        try {
            replacement = await createProtectedRecord(
                loadedPreparation.record.id,
                context,
                plaintext,
                loadedAction.rootKey,
            );
        } finally {
            plaintext.fill(0);
            context.fill(0);
        }
        await this.durableState.replaceExact(
            'preparations',
            loadedPreparation.record,
            replacement,
        );
        const retained = await this.durableState.readProtected(
            'preparations',
            loadedPreparation.record.id,
        );
        if (retained === undefined) {
            throw new DurableStateError(
                'StateLost',
                'The published preparation disappeared after persistence.',
            );
        }
        const reloaded = await this.loadPreparationState(
            action,
            loadedAction.state.rosterIdentity,
            retained,
        );
        try {
            this.validatePreparationState(
                action,
                canonicalRosterBytes,
                loadedAction.state,
                reloaded.state,
            );
            return copyPublishedPreparationPackage(reloaded.state);
        } finally {
            zeroPreparationState(reloaded.state);
        }
    }

    private validatePreparationState(
        action: PrivatePreparationActionContext,
        canonicalRosterBytes: Uint8Array,
        actionState: ActionState,
        state: PreparationState,
    ): void {
        const materialContext = {
            participantCount: completionProfileParticipantCount,
            actionProposalIdentity: action.actionProposalIdentity,
            rosterIdentity: actionState.rosterIdentity,
            preparationAttempt: state.preparationAttempt,
            predecessorIdentity: action.predecessorIdentity,
            senderPosition: action.participantPosition,
        } as const;
        const material = this.preparationMaterialRuntime.generate(
            materialContext,
            state.contributionOpenings,
            state.pairwiseMasters,
        );
        try {
            const parent = this.preparationParentRuntime.encode({
                ...materialContext,
                subsetCommitments: material.subsetCommitments,
                privateBodyIdentities: state.privateBodyIdentities,
            });
            if (
                !bytesEqual(parent.body, state.parentBody) ||
                !bytesEqual(parent.identity, state.parentIdentity)
            ) {
                throw new DurableStateError(
                    'CorruptState',
                    'The retained preparation parent does not match its source material.',
                );
            }
            const recipients = remotePositions(action.participantPosition);
            for (const [
                recipientIndex,
                recipientPosition,
            ] of recipients.entries()) {
                const plaintext = material.recipientPlaintexts[recipientIndex];
                const privateBody = state.privateBodies[recipientIndex];
                const expectedBodyIdentity =
                    state.privateBodyIdentities[recipientIndex];
                if (
                    plaintext === undefined ||
                    privateBody === undefined ||
                    expectedBodyIdentity === undefined
                ) {
                    throw new DurableStateError(
                        'CorruptState',
                        'The retained preparation omitted a recipient.',
                    );
                }
                this.preparationMaterialRuntime.verifyPlaintext(
                    materialContext,
                    recipientPosition,
                    state.parentBody,
                    plaintext,
                );
                if (state.phase === publishedPreparationPhase) {
                    const carrier =
                        this.preparationParentRuntime.verifyPrivateCarrier(
                            {
                                participantCount:
                                    completionProfileParticipantCount,
                                actionProposalIdentity:
                                    action.actionProposalIdentity,
                                rosterIdentity: actionState.rosterIdentity,
                                preparationAttempt: state.preparationAttempt,
                                predecessorIdentity: action.predecessorIdentity,
                                recipientPosition,
                            },
                            canonicalRosterBytes,
                            state.parentBody,
                            state.parentSignature,
                            privateBody,
                        );
                    if (
                        carrier.senderPosition !== action.participantPosition ||
                        carrier.recipientPosition !== recipientPosition ||
                        !bytesEqual(
                            carrier.parentIdentity,
                            state.parentIdentity,
                        ) ||
                        !bytesEqual(carrier.bodyIdentity, expectedBodyIdentity)
                    ) {
                        throw new DurableStateError(
                            'CorruptState',
                            'A retained private preparation carrier has the wrong identity.',
                        );
                    }
                }
            }
        } finally {
            for (const plaintext of material.recipientPlaintexts) {
                plaintext.fill(0);
            }
        }
    }

    private async openConsumedPrivatePreparation(
        action: PrivatePreparationActionContext,
        canonicalRosterBytes: Uint8Array,
        parentBody: Uint8Array,
        privateBody: Uint8Array,
        loadedAction: LoadedActionState,
        loadedSlot: LoadedPrivatePreparationSlotState,
    ): Promise<PrivatePreparationConsumption> {
        const senderPosition = loadedSlot.state.senderPosition;
        const mailboxEncapsulationKey = this.rosterRuntime.resolveMailboxKey(
            loadedAction.state.rosterIdentity,
            senderPosition,
            action.participantPosition,
            canonicalRosterBytes,
        );
        const privateContext: PrivatePreparationContextInput = {
            participantCount: completionProfileParticipantCount,
            actionProposalIdentity: action.actionProposalIdentity,
            rosterIdentity: loadedAction.state.rosterIdentity,
            preparationAttempt: loadedSlot.state.preparationAttempt,
            predecessorIdentity: action.predecessorIdentity,
            senderPosition,
            recipientPosition: action.participantPosition,
        };
        let capabilityIsLive = true;
        const openOnce = (): Uint8Array => {
            if (!capabilityIsLive) {
                throw new DurableStateError(
                    'Conflict',
                    'The private-opening capability is already consumed.',
                );
            }
            capabilityIsLive = false;
            return this.privatePreparationBodyRuntime.open(
                privateContext,
                mailboxEncapsulationKey,
                loadedAction.state.mailboxDecapsulationKey,
                privateBody,
            );
        };
        let plaintext: Uint8Array | undefined;
        try {
            plaintext = openOnce();
            const verifiedPlaintextIdentity =
                this.preparationMaterialRuntime.verifyPlaintext(
                    {
                        participantCount: completionProfileParticipantCount,
                        actionProposalIdentity: action.actionProposalIdentity,
                        rosterIdentity: loadedAction.state.rosterIdentity,
                        preparationAttempt: loadedSlot.state.preparationAttempt,
                        predecessorIdentity: action.predecessorIdentity,
                        senderPosition,
                    },
                    action.participantPosition,
                    parentBody,
                    plaintext,
                );
            const resolvedState: PrivatePreparationSlotState = {
                ...loadedSlot.state,
                phase: resolvedPrivatePreparationPhase,
                generation: loadedSlot.state.generation + 1n,
                verifiedPlaintextIdentity,
                plaintext: Uint8Array.from(plaintext),
            };
            await this.replacePrivatePreparationSlot(
                action,
                loadedAction.rootKey,
                loadedAction.state.rosterIdentity,
                loadedSlot,
                resolvedState,
            );
            return { senderPosition, status: 'resolved' };
        } catch (error: unknown) {
            await this.burnPrivatePreparationSlot(
                action,
                loadedAction.rootKey,
                loadedAction.state.rosterIdentity,
                loadedSlot,
            );
            throw error;
        } finally {
            capabilityIsLive = false;
            mailboxEncapsulationKey.fill(0);
            plaintext?.fill(0);
        }
    }

    private async burnPrivatePreparationSlot(
        action: PrivatePreparationActionContext,
        rootKey: CryptoKey,
        rosterIdentity: Uint8Array,
        loadedSlot: LoadedPrivatePreparationSlotState,
    ): Promise<void> {
        const burnedState: PrivatePreparationSlotState = {
            ...loadedSlot.state,
            phase: burnedPrivatePreparationPhase,
            generation: loadedSlot.state.generation + 1n,
            verifiedPlaintextIdentity: new Uint8Array(identityByteLength),
            plaintext: new Uint8Array(preparationPlaintextByteLength),
        };
        await this.replacePrivatePreparationSlot(
            action,
            rootKey,
            rosterIdentity,
            loadedSlot,
            burnedState,
        );
    }

    private async replacePrivatePreparationSlot(
        action: PrivatePreparationActionContext,
        rootKey: CryptoKey,
        rosterIdentity: Uint8Array,
        loadedSlot: LoadedPrivatePreparationSlotState,
        replacementState: PrivatePreparationSlotState,
    ): Promise<void> {
        const plaintext = encodePrivatePreparationSlotState(replacementState);
        const context = encodeLocalRecordContext(
            privatePreparationSlotLocalContext(
                this.configuration,
                action,
                rosterIdentity,
                replacementState.generation,
                replacementState.senderPosition,
            ),
        );
        let replacement: ProtectedRecord;
        try {
            replacement = await createProtectedRecord(
                loadedSlot.record.id,
                context,
                plaintext,
                rootKey,
            );
        } finally {
            plaintext.fill(0);
            context.fill(0);
        }
        await this.durableState.replaceExact(
            'slots',
            loadedSlot.record,
            replacement,
        );
        const retained = await this.durableState.readProtected(
            'slots',
            loadedSlot.record.id,
        );
        if (retained === undefined) {
            throw new DurableStateError(
                'StateLost',
                'The private-preparation slot disappeared after replacement.',
            );
        }
        const reloaded = await this.loadPrivatePreparationSlot(
            action,
            rosterIdentity,
            replacementState.senderPosition,
            retained,
        );
        try {
            if (
                reloaded.state.phase !== replacementState.phase ||
                reloaded.state.generation !== replacementState.generation ||
                !bytesEqual(
                    reloaded.state.parentIdentity,
                    replacementState.parentIdentity,
                ) ||
                !bytesEqual(
                    reloaded.state.bodyIdentity,
                    replacementState.bodyIdentity,
                ) ||
                !bytesEqual(
                    reloaded.state.verifiedPlaintextIdentity,
                    replacementState.verifiedPlaintextIdentity,
                ) ||
                !bytesEqual(
                    reloaded.state.plaintext,
                    replacementState.plaintext,
                )
            ) {
                throw new DurableStateError(
                    'StateLost',
                    'The replaced private-preparation slot is inconsistent.',
                );
            }
        } finally {
            zeroPrivatePreparationSlotState(reloaded.state);
        }
    }

    private assertSlotMatchesCarrier(
        state: PrivatePreparationSlotState,
        preparationAttempt: number,
        parentIdentity: Uint8Array,
        bodyIdentity: Uint8Array,
    ): void {
        if (
            state.preparationAttempt !== preparationAttempt ||
            !bytesEqual(state.parentIdentity, parentIdentity) ||
            !bytesEqual(state.bodyIdentity, bodyIdentity)
        ) {
            throw new DurableStateError(
                'Conflict',
                'The private-preparation slot is already bound to another carrier.',
            );
        }
    }

    private async loadPreparationState(
        action: PrivatePreparationActionContext,
        rosterIdentity: Uint8Array,
        record: ProtectedRecord,
    ): Promise<LoadedPreparationState> {
        const rootKey = await this.durableState.readRoot();
        if (rootKey === undefined) {
            throw new DurableStateError(
                'StateLost',
                'The browser-local root is absent for retained preparation state.',
            );
        }
        const localContext = decodeLocalRecordContext(record.context);
        const expectedContext = encodeLocalRecordContext(localContext);
        let plaintext: Uint8Array | undefined;
        try {
            plaintext = await openProtectedRecord(
                record,
                expectedContext,
                rootKey,
            );
            const state = decodePreparationState(plaintext);
            if (
                state.generation !== localContext.generation ||
                BigInt(state.preparationAttempt) !==
                    localContext.operationOrdinal ||
                localContext.objectKind !== preparationStateKind ||
                localContext.peerPosition !== noPeerPosition ||
                localContext.participantPosition !==
                    action.participantPosition ||
                !bytesEqual(
                    localContext.runtimeIdentity,
                    this.configuration.runtimeIdentity,
                ) ||
                !bytesEqual(
                    localContext.candidateBuildIdentity,
                    this.configuration.candidateBuildIdentity,
                ) ||
                !bytesEqual(
                    localContext.actionProposalIdentity,
                    action.actionProposalIdentity,
                ) ||
                !bytesEqual(localContext.rosterIdentity, rosterIdentity) ||
                !bytesEqual(
                    localContext.predecessorIdentity,
                    action.predecessorIdentity,
                )
            ) {
                zeroPreparationState(state);
                throw new DurableStateError(
                    'StateLost',
                    'The retained preparation does not match its authenticated context.',
                );
            }
            return { record, state };
        } finally {
            expectedContext.fill(0);
            plaintext?.fill(0);
        }
    }

    private async loadPrivatePreparationSlot(
        action: PrivatePreparationActionContext,
        rosterIdentity: Uint8Array,
        senderPosition: number,
        record: ProtectedRecord,
    ): Promise<LoadedPrivatePreparationSlotState> {
        const rootKey = await this.durableState.readRoot();
        if (rootKey === undefined) {
            throw new DurableStateError(
                'StateLost',
                'The browser-local root is absent for a private-preparation slot.',
            );
        }
        const localContext = decodeLocalRecordContext(record.context);
        const expectedContext = encodeLocalRecordContext(localContext);
        let plaintext: Uint8Array | undefined;
        try {
            plaintext = await openProtectedRecord(
                record,
                expectedContext,
                rootKey,
            );
            const state = decodePrivatePreparationSlotState(plaintext);
            if (
                state.generation !== localContext.generation ||
                state.senderPosition !== senderPosition ||
                localContext.operationOrdinal !==
                    privatePreparationOperationOrdinal ||
                localContext.objectKind !== privatePreparationSlotStateKind ||
                localContext.peerPosition !== senderPosition ||
                localContext.participantPosition !==
                    action.participantPosition ||
                !bytesEqual(
                    localContext.runtimeIdentity,
                    this.configuration.runtimeIdentity,
                ) ||
                !bytesEqual(
                    localContext.candidateBuildIdentity,
                    this.configuration.candidateBuildIdentity,
                ) ||
                !bytesEqual(
                    localContext.actionProposalIdentity,
                    action.actionProposalIdentity,
                ) ||
                !bytesEqual(localContext.rosterIdentity, rosterIdentity) ||
                !bytesEqual(
                    localContext.predecessorIdentity,
                    action.predecessorIdentity,
                )
            ) {
                zeroPrivatePreparationSlotState(state);
                throw new DurableStateError(
                    'StateLost',
                    'The private-preparation slot does not match its authenticated context.',
                );
            }
            return { record, state };
        } finally {
            expectedContext.fill(0);
            plaintext?.fill(0);
        }
    }

    private async loadFinalityState(
        action: PrivatePreparationActionContext,
        rosterIdentity: Uint8Array,
        record: ProtectedRecord,
    ): Promise<LoadedFinalityState> {
        const rootKey = await this.durableState.readRoot();
        if (rootKey === undefined) {
            throw new DurableStateError(
                'StateLost',
                'The browser-local root is absent for retained finality state.',
            );
        }
        const localContext = decodeLocalRecordContext(record.context);
        const expectedContext = encodeLocalRecordContext(localContext);
        let plaintext: Uint8Array | undefined;
        try {
            plaintext = await openProtectedRecord(
                record,
                expectedContext,
                rootKey,
            );
            const state = decodeFinalityState(plaintext);
            try {
                assertTerminalLocalContext(
                    state.generation,
                    localContext,
                    this.configuration,
                    action,
                    rosterIdentity,
                    finalityStateKind,
                );
                return { record, state };
            } catch (error: unknown) {
                zeroFinalityState(state);
                throw error;
            }
        } finally {
            expectedContext.fill(0);
            plaintext?.fill(0);
        }
    }

    private async loadNoResultState(
        action: PrivatePreparationActionContext,
        rosterIdentity: Uint8Array,
        record: ProtectedRecord,
    ): Promise<LoadedNoResultState> {
        const rootKey = await this.durableState.readRoot();
        if (rootKey === undefined) {
            throw new DurableStateError(
                'StateLost',
                'The browser-local root is absent for retained no-result state.',
            );
        }
        const localContext = decodeLocalRecordContext(record.context);
        const expectedContext = encodeLocalRecordContext(localContext);
        let plaintext: Uint8Array | undefined;
        try {
            plaintext = await openProtectedRecord(
                record,
                expectedContext,
                rootKey,
            );
            const state = decodeNoResultState(plaintext);
            try {
                assertTerminalLocalContext(
                    state.generation,
                    localContext,
                    this.configuration,
                    action,
                    rosterIdentity,
                    noResultStateKind,
                );
            } catch (error: unknown) {
                zeroNoResultState(state);
                throw error;
            }
            return { record, state };
        } finally {
            expectedContext.fill(0);
            plaintext?.fill(0);
        }
    }

    private async loadSourceState(
        action: PrivatePreparationActionContext,
        rosterIdentity: Uint8Array,
        record: ProtectedRecord,
    ): Promise<LoadedSourceState> {
        const rootKey = await this.durableState.readRoot();
        if (rootKey === undefined) {
            throw new DurableStateError(
                'StateLost',
                'The browser-local root is absent for retained source state.',
            );
        }
        const localContext = decodeLocalRecordContext(record.context);
        const expectedContext = encodeLocalRecordContext(localContext);
        let plaintext: Uint8Array | undefined;
        try {
            plaintext = await openProtectedRecord(
                record,
                expectedContext,
                rootKey,
            );
            const state = decodeSourceState(plaintext);
            if (
                state.generation !== localContext.generation ||
                localContext.operationOrdinal !== sourceOperationOrdinal ||
                localContext.objectKind !== sourceStateKind ||
                localContext.peerPosition !== noPeerPosition ||
                localContext.participantPosition !==
                    action.participantPosition ||
                !bytesEqual(
                    localContext.runtimeIdentity,
                    this.configuration.runtimeIdentity,
                ) ||
                !bytesEqual(
                    localContext.candidateBuildIdentity,
                    this.configuration.candidateBuildIdentity,
                ) ||
                !bytesEqual(
                    localContext.actionProposalIdentity,
                    action.actionProposalIdentity,
                ) ||
                !bytesEqual(localContext.rosterIdentity, rosterIdentity) ||
                !bytesEqual(
                    localContext.predecessorIdentity,
                    action.predecessorIdentity,
                )
            ) {
                zeroSourceState(state);
                throw new DurableStateError(
                    'StateLost',
                    'The retained source does not match its authenticated context.',
                );
            }
            return { record, state };
        } finally {
            expectedContext.fill(0);
            plaintext?.fill(0);
        }
    }

    private async loadActionState(
        action: PrivatePreparationActionContext,
        record: ProtectedRecord,
    ): Promise<LoadedActionState> {
        const rootKey = await this.durableState.readRoot();
        if (rootKey === undefined) {
            throw new DurableStateError(
                'StateLost',
                'The browser-local root is absent for retained action state.',
            );
        }
        const localContext = decodeLocalRecordContext(record.context);
        const expectedContext = encodeLocalRecordContext(localContext);
        let plaintext: Uint8Array | undefined;
        try {
            plaintext = await openProtectedRecord(
                record,
                expectedContext,
                rootKey,
            );
            const state = decodeActionState(plaintext);
            assertActionStateContext(
                state,
                localContext,
                this.configuration,
                action,
            );
            const rosterIdentity = this.rosterRuntime.verifyCredentials(
                state.canonicalRosterBytes,
                action.participantPosition,
                state.signingSecretKey,
                state.mailboxDecapsulationKey,
            );
            if (!bytesEqual(rosterIdentity, state.rosterIdentity)) {
                zeroActionState(state);
                throw new DurableStateError(
                    'CorruptState',
                    'The retained action credentials do not match the frozen roster.',
                );
            }
            return { record, rootKey, state };
        } finally {
            expectedContext.fill(0);
            plaintext?.fill(0);
        }
    }
}

type WorkerInstallationOptions = Readonly<{
    persistentStorageRequired: boolean;
    unpinnedKernelAllowed: boolean;
    afterDurableConsume?: () => Promise<void> | void;
    afterDurableSourceBind?: () => Promise<void> | void;
}>;

const failureResponse = (
    requestId: number,
    error: unknown,
): PrivatePreparationWorkerFailure => {
    if (error instanceof DurableStateError) {
        return {
            requestId,
            ok: false,
            error: { code: error.code, message: error.message },
        };
    }
    if (error instanceof TypeError || error instanceof RangeError) {
        return {
            requestId,
            ok: false,
            error: { code: 'InvalidRequest', message: error.message },
        };
    }
    return {
        requestId,
        ok: false,
        error: {
            code: 'ProtocolRefusal',
            message:
                error instanceof Error
                    ? error.message
                    : 'The construction verifier refused the operation.',
        },
    };
};

const responseTransferables = (
    response: PrivatePreparationWorkerResponse,
): Transferable[] => {
    if (!response.ok) {
        return [];
    }
    const { result } = response;
    if ('parentBody' in result) {
        return [
            result.parentBody.buffer,
            result.parentSignature.buffer,
            ...result.privateBodies.map((body) => body.buffer),
        ];
    }
    if ('sourceBody' in result) {
        return [result.sourceBody.buffer, result.sourceSignature.buffer];
    }
    if ('targetBody' in result) {
        return [
            result.targetBody.buffer,
            result.targetIdentity.buffer,
            result.finalitySignature.buffer,
        ];
    }
    return [];
};

export const installPrivatePreparationWorker = (
    scope: DedicatedWorkerGlobalScope,
    options: WorkerInstallationOptions,
): void => {
    let runtimePromise: Promise<PrivatePreparationWorkerRuntime> | undefined;
    scope.addEventListener(
        'message',
        (event: MessageEvent<PrivatePreparationWorkerRequest>) => {
            const request = event.data;
            void (async () => {
                let response: PrivatePreparationWorkerResponse;
                try {
                    if (
                        typeof request !== 'object' ||
                        request === null ||
                        !Number.isSafeInteger(request.requestId) ||
                        request.requestId < 0
                    ) {
                        throw new TypeError('The worker request is malformed.');
                    }
                    if (request.operation === 'initialize') {
                        if (runtimePromise !== undefined) {
                            throw new TypeError(
                                'The worker is already initialized.',
                            );
                        }
                        runtimePromise = PrivatePreparationWorkerRuntime.create(
                            request.input,
                            options.persistentStorageRequired,
                            options.unpinnedKernelAllowed,
                            options.afterDurableConsume,
                            options.afterDurableSourceBind,
                        );
                        await runtimePromise;
                        response = {
                            requestId: request.requestId,
                            ok: true,
                            result: { initialized: true },
                        };
                    } else {
                        if (runtimePromise === undefined) {
                            throw new TypeError(
                                'The worker has not been initialized.',
                            );
                        }
                        const runtime = await runtimePromise;
                        if (
                            request.operation === 'create-preparation-package'
                        ) {
                            response = {
                                requestId: request.requestId,
                                ok: true,
                                result: await runtime.createPreparationPackage(
                                    request.input,
                                ),
                            };
                        } else if (
                            request.operation === 'consume-private-preparation'
                        ) {
                            response = {
                                requestId: request.requestId,
                                ok: true,
                                result: await runtime.consumePrivatePreparation(
                                    request.input,
                                ),
                            };
                        } else if (
                            request.operation === 'create-source-package'
                        ) {
                            response = {
                                requestId: request.requestId,
                                ok: true,
                                result: await runtime.createSourcePackage(
                                    request.input,
                                ),
                            };
                        } else if (
                            request.operation === 'create-finality-signature'
                        ) {
                            response = {
                                requestId: request.requestId,
                                ok: true,
                                result: await runtime.createFinalitySignature(
                                    request.input,
                                ),
                            };
                        } else if (request.operation === 'finalize-no-result') {
                            response = {
                                requestId: request.requestId,
                                ok: true,
                                result: await runtime.finalizeNoResult(
                                    request.input,
                                ),
                            };
                        } else if (request.operation === 'read-tally-result') {
                            response = {
                                requestId: request.requestId,
                                ok: true,
                                result: await runtime.readTallyResult(
                                    request.input,
                                ),
                            };
                        } else {
                            throw new TypeError(
                                'The requested worker operation is not implemented.',
                            );
                        }
                    }
                } catch (error: unknown) {
                    const requestId =
                        typeof request === 'object' &&
                        request !== null &&
                        Number.isSafeInteger(request.requestId)
                            ? request.requestId
                            : 0;
                    response = failureResponse(requestId, error);
                }
                scope.postMessage(response, responseTransferables(response));
            })();
        },
    );
};
