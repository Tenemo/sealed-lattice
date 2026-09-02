import { maximumFoundationCopiedBufferByteLength } from './foundation-contract.js';
import {
    paddedTallyAllocationNonceByteLength,
    paddedTallyCheckpointKeyByteLength,
    type PaddedTallyPlan,
} from './padded-tally-runtime.js';
import { actionSignatureCarrierByteLength } from './preparation-parent-runtime.js';
import { DurableStateError } from './private-preparation-durable-state.js';

const stateVersion = 1;
const identityByteLength = 64;
const digestByteLength = 32;
const completionProfileParticipantCount = 10;
const sourceBodyIdentityVectorByteLength =
    completionProfileParticipantCount * identityByteLength;
const maximumChunkByteLength = 480_000;
const maximumTerminalBodyByteLength = 1_024;

export const paddedTallyGenerationStateKind = 10;
export const paddedTallyEvaluationStateKind = 11;

export const allocatedPaddedTallyGenerationPhase = 1;
export const retainedPaddedTallyChunkPhase = 2;
export const completedPaddedTallyGenerationPhase = 3;

export const initializedPaddedTallyEvaluationPhase = 1;
export const pendingPaddedTallyEvaluationPhase = 2;
export const completedPaddedTallyEvaluationPhase = 3;

type PaddedTallyGenerationCommonState = {
    generation: bigint;
    preparationAttempt: number;
    verifiedPreparationRoot: Uint8Array;
    targetIdentity: Uint8Array;
    sourceBodyIdentities: Uint8Array;
    topCount: number;
    chunkCount: number;
    allocationNonce: Uint8Array;
};

export type AllocatedPaddedTallyGenerationState =
    PaddedTallyGenerationCommonState & {
        phase: typeof allocatedPaddedTallyGenerationPhase;
        checkpointKey: Uint8Array;
        checkpoint: Uint8Array;
    };

export type RetainedPaddedTallyChunkState = PaddedTallyGenerationCommonState & {
    phase: typeof retainedPaddedTallyChunkPhase;
    chunkOrdinal: number;
    chunk: Uint8Array;
    chunkIdentity: Uint8Array;
    checkpointKey: Uint8Array;
    nextCheckpoint: Uint8Array;
};

export type CompletedPaddedTallyGenerationState =
    PaddedTallyGenerationCommonState & {
        phase: typeof completedPaddedTallyGenerationPhase;
        chunkOrdinal: number;
        chunk: Uint8Array;
        chunkIdentity: Uint8Array;
        manifest: Uint8Array;
        manifestIdentity: Uint8Array;
        activationSignature: Uint8Array;
    };

export type PaddedTallyGenerationState =
    | AllocatedPaddedTallyGenerationState
    | CompletedPaddedTallyGenerationState
    | RetainedPaddedTallyChunkState;

type PaddedTallyEvaluationCommonState = {
    generation: bigint;
    targetIdentity: Uint8Array;
    topCount: number;
    chunkCount: number;
    activationInventoryDigest: Uint8Array;
};

type InitializedPaddedTallyEvaluationState =
    PaddedTallyEvaluationCommonState & {
        phase: typeof initializedPaddedTallyEvaluationPhase;
        checkpointKey: Uint8Array;
        checkpoint: Uint8Array;
    };

export type PendingPaddedTallyEvaluationState =
    PaddedTallyEvaluationCommonState & {
        phase: typeof pendingPaddedTallyEvaluationPhase;
        lastChunkOrdinal: number;
        lastChunkSetDigest: Uint8Array;
        checkpointKey: Uint8Array;
        checkpoint: Uint8Array;
    };

export type CompletedPaddedTallyEvaluationState =
    PaddedTallyEvaluationCommonState & {
        phase: typeof completedPaddedTallyEvaluationPhase;
        lastChunkOrdinal: number;
        lastChunkSetDigest: Uint8Array;
        batchIdentity: Uint8Array;
        terminalBody: Uint8Array;
        terminalIdentity: Uint8Array;
        outputSchemaIdentity: Uint8Array;
        acceptedBallotAuthorshipBitmap: number;
        orderedOptionPositions: readonly number[] | undefined;
    };

export type PaddedTallyEvaluationState =
    | CompletedPaddedTallyEvaluationState
    | InitializedPaddedTallyEvaluationState
    | PendingPaddedTallyEvaluationState;

class StateWriter {
    readonly #bytes: Uint8Array;
    #offset = 0;

    constructor(byteLength: number) {
        if (
            !Number.isSafeInteger(byteLength) ||
            byteLength <= 0 ||
            byteLength > maximumFoundationCopiedBufferByteLength
        ) {
            throw new DurableStateError(
                'CorruptState',
                'The padded-tally durable state has an invalid byte length.',
            );
        }
        this.#bytes = new Uint8Array(byteLength);
    }

    writeU8(value: number): void {
        this.#bytes[this.#offset] = value;
        this.#offset += 1;
    }

    writeU16(value: number): void {
        new DataView(this.#bytes.buffer).setUint16(this.#offset, value, true);
        this.#offset += 2;
    }

    writeU32(value: number): void {
        new DataView(this.#bytes.buffer).setUint32(this.#offset, value, true);
        this.#offset += 4;
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

    writeVariable(bytes: Uint8Array): void {
        this.writeU32(bytes.byteLength);
        this.writeFixed(bytes);
    }

    finish(): Uint8Array {
        if (this.#offset !== this.#bytes.byteLength) {
            this.#bytes.fill(0);
            throw new DurableStateError(
                'CorruptState',
                'The padded-tally durable state length is inconsistent.',
            );
        }
        return this.#bytes;
    }
}

class StateReader {
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

    readU32(): number {
        const bytes = this.readFixed(4);
        return new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength,
        ).getUint32(0, true);
    }

    readU64(): bigint {
        const bytes = this.readFixed(8);
        return new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength,
        ).getBigUint64(0, true);
    }

    readFixed(byteLength: number): Uint8Array {
        const end = this.#offset + byteLength;
        if (
            !Number.isSafeInteger(byteLength) ||
            byteLength < 0 ||
            end > this.bytes.byteLength
        ) {
            throw new DurableStateError(
                'CorruptState',
                'The padded-tally durable state is truncated.',
            );
        }
        const result = Uint8Array.from(this.bytes.subarray(this.#offset, end));
        this.#offset = end;
        return result;
    }

    readVariable(maximumByteLength: number): Uint8Array {
        const byteLength = this.readU32();
        if (byteLength === 0 || byteLength > maximumByteLength) {
            throw new DurableStateError(
                'CorruptState',
                'The padded-tally durable field has an invalid byte length.',
            );
        }
        return this.readFixed(byteLength);
    }

    finish(): void {
        if (this.#offset !== this.bytes.byteLength) {
            throw new DurableStateError(
                'CorruptState',
                'The padded-tally durable state has trailing bytes.',
            );
        }
    }
}

const requireExactLength = (
    bytes: Uint8Array,
    byteLength: number,
    fieldName: string,
): void => {
    if (bytes.byteLength !== byteLength) {
        throw new DurableStateError(
            'CorruptState',
            `The retained ${fieldName} has the wrong byte length.`,
        );
    }
};

const isZero = (bytes: Uint8Array): boolean => {
    let aggregate = 0;
    for (const byte of bytes) aggregate |= byte;
    return aggregate === 0;
};

const requireCommonGenerationState = (
    state: PaddedTallyGenerationState,
    plan: PaddedTallyPlan,
): void => {
    requireExactLength(
        state.verifiedPreparationRoot,
        identityByteLength,
        'verified preparation root',
    );
    requireExactLength(
        state.targetIdentity,
        identityByteLength,
        'target identity',
    );
    requireExactLength(
        state.sourceBodyIdentities,
        sourceBodyIdentityVectorByteLength,
        'source identity vector',
    );
    requireExactLength(
        state.allocationNonce,
        paddedTallyAllocationNonceByteLength,
        'allocation nonce',
    );
    if (
        state.preparationAttempt < 0 ||
        state.preparationAttempt > 0xffff ||
        state.topCount !== plan.topCount ||
        state.chunkCount !== plan.chunks.length ||
        state.chunkCount < 1
    ) {
        throw new DurableStateError(
            'CorruptState',
            'The retained tally generation has invalid common fields.',
        );
    }
};

const requireCheckpointKey = (checkpointKey: Uint8Array): void => {
    requireExactLength(
        checkpointKey,
        paddedTallyCheckpointKeyByteLength,
        'checkpoint key',
    );
    if (isZero(checkpointKey)) {
        throw new DurableStateError(
            'CorruptState',
            'The retained checkpoint key is all zero.',
        );
    }
};

export const validatePaddedTallyGenerationState = (
    state: PaddedTallyGenerationState,
    plan: PaddedTallyPlan,
): void => {
    requireCommonGenerationState(state, plan);
    if (state.phase === allocatedPaddedTallyGenerationPhase) {
        requireCheckpointKey(state.checkpointKey);
        if (state.generation !== 1n || state.checkpoint.byteLength === 0) {
            throw new DurableStateError(
                'CorruptState',
                'The retained tally generation allocation is invalid.',
            );
        }
        return;
    }
    const chunkPlan = plan.chunks[state.chunkOrdinal];
    if (
        chunkPlan === undefined ||
        state.generation !== BigInt(state.chunkOrdinal) + 2n ||
        state.chunk.byteLength !== chunkPlan.chunkByteLength ||
        state.chunk.byteLength > maximumChunkByteLength
    ) {
        throw new DurableStateError(
            'CorruptState',
            'The retained tally chunk is inconsistent with the plan.',
        );
    }
    requireExactLength(
        state.chunkIdentity,
        identityByteLength,
        'chunk identity',
    );
    if (state.phase === retainedPaddedTallyChunkPhase) {
        requireCheckpointKey(state.checkpointKey);
        if (
            state.chunkOrdinal + 1 >= state.chunkCount ||
            state.nextCheckpoint.byteLength === 0
        ) {
            throw new DurableStateError(
                'CorruptState',
                'The retained pending tally chunk is invalid.',
            );
        }
        return;
    }
    if (state.chunkOrdinal + 1 !== state.chunkCount) {
        throw new DurableStateError(
            'CorruptState',
            'The retained completed tally has the wrong final ordinal.',
        );
    }
    requireExactLength(
        state.manifest,
        plan.manifestByteLength,
        'activation manifest',
    );
    requireExactLength(
        state.manifestIdentity,
        identityByteLength,
        'manifest identity',
    );
    requireExactLength(
        state.activationSignature,
        actionSignatureCarrierByteLength,
        'activation signature',
    );
    if (isZero(state.activationSignature)) {
        throw new DurableStateError(
            'CorruptState',
            'The retained completed tally omits its activation signature.',
        );
    }
};

const generationCommonByteLength =
    1 +
    1 +
    8 +
    2 +
    identityByteLength +
    identityByteLength +
    sourceBodyIdentityVectorByteLength +
    2 +
    2 +
    paddedTallyAllocationNonceByteLength;

const writeGenerationCommon = (
    writer: StateWriter,
    state: PaddedTallyGenerationState,
): void => {
    writer.writeU8(stateVersion);
    writer.writeU8(state.phase);
    writer.writeU64(state.generation);
    writer.writeU16(state.preparationAttempt);
    writer.writeFixed(state.verifiedPreparationRoot);
    writer.writeFixed(state.targetIdentity);
    writer.writeFixed(state.sourceBodyIdentities);
    writer.writeU16(state.topCount);
    writer.writeU16(state.chunkCount);
    writer.writeFixed(state.allocationNonce);
};

export const encodePaddedTallyGenerationState = (
    state: PaddedTallyGenerationState,
    plan: PaddedTallyPlan,
): Uint8Array => {
    validatePaddedTallyGenerationState(state, plan);
    if (state.phase === allocatedPaddedTallyGenerationPhase) {
        const writer = new StateWriter(
            generationCommonByteLength +
                paddedTallyCheckpointKeyByteLength +
                4 +
                state.checkpoint.byteLength,
        );
        writeGenerationCommon(writer, state);
        writer.writeFixed(state.checkpointKey);
        writer.writeVariable(state.checkpoint);
        return writer.finish();
    }
    if (state.phase === retainedPaddedTallyChunkPhase) {
        const writer = new StateWriter(
            generationCommonByteLength +
                4 +
                4 +
                state.chunk.byteLength +
                identityByteLength +
                paddedTallyCheckpointKeyByteLength +
                4 +
                state.nextCheckpoint.byteLength,
        );
        writeGenerationCommon(writer, state);
        writer.writeU32(state.chunkOrdinal);
        writer.writeVariable(state.chunk);
        writer.writeFixed(state.chunkIdentity);
        writer.writeFixed(state.checkpointKey);
        writer.writeVariable(state.nextCheckpoint);
        return writer.finish();
    }
    const writer = new StateWriter(
        generationCommonByteLength +
            4 +
            4 +
            state.chunk.byteLength +
            identityByteLength +
            4 +
            state.manifest.byteLength +
            identityByteLength +
            actionSignatureCarrierByteLength,
    );
    writeGenerationCommon(writer, state);
    writer.writeU32(state.chunkOrdinal);
    writer.writeVariable(state.chunk);
    writer.writeFixed(state.chunkIdentity);
    writer.writeVariable(state.manifest);
    writer.writeFixed(state.manifestIdentity);
    writer.writeFixed(state.activationSignature);
    return writer.finish();
};

export const decodePaddedTallyGenerationState = (
    bytes: Uint8Array,
    plan: PaddedTallyPlan,
): PaddedTallyGenerationState => {
    const reader = new StateReader(bytes);
    if (reader.readU8() !== stateVersion) {
        throw new DurableStateError(
            'CorruptState',
            'The retained tally generation has the wrong version.',
        );
    }
    const phase = reader.readU8();
    const common = {
        generation: reader.readU64(),
        preparationAttempt: reader.readU16(),
        verifiedPreparationRoot: reader.readFixed(identityByteLength),
        targetIdentity: reader.readFixed(identityByteLength),
        sourceBodyIdentities: reader.readFixed(
            sourceBodyIdentityVectorByteLength,
        ),
        topCount: reader.readU16(),
        chunkCount: reader.readU16(),
        allocationNonce: reader.readFixed(paddedTallyAllocationNonceByteLength),
    };
    let state: PaddedTallyGenerationState;
    if (phase === allocatedPaddedTallyGenerationPhase) {
        state = {
            ...common,
            phase,
            checkpointKey: reader.readFixed(paddedTallyCheckpointKeyByteLength),
            checkpoint: reader.readVariable(
                maximumFoundationCopiedBufferByteLength,
            ),
        };
    } else if (phase === retainedPaddedTallyChunkPhase) {
        state = {
            ...common,
            phase,
            chunkOrdinal: reader.readU32(),
            chunk: reader.readVariable(maximumChunkByteLength),
            chunkIdentity: reader.readFixed(identityByteLength),
            checkpointKey: reader.readFixed(paddedTallyCheckpointKeyByteLength),
            nextCheckpoint: reader.readVariable(
                maximumFoundationCopiedBufferByteLength,
            ),
        };
    } else if (phase === completedPaddedTallyGenerationPhase) {
        state = {
            ...common,
            phase,
            chunkOrdinal: reader.readU32(),
            chunk: reader.readVariable(maximumChunkByteLength),
            chunkIdentity: reader.readFixed(identityByteLength),
            manifest: reader.readVariable(
                maximumFoundationCopiedBufferByteLength,
            ),
            manifestIdentity: reader.readFixed(identityByteLength),
            activationSignature: reader.readFixed(
                actionSignatureCarrierByteLength,
            ),
        };
    } else {
        throw new DurableStateError(
            'CorruptState',
            'The retained tally generation has an invalid phase.',
        );
    }
    reader.finish();
    try {
        validatePaddedTallyGenerationState(state, plan);
        return state;
    } catch (error) {
        zeroPaddedTallyGenerationState(state);
        throw error;
    }
};

export const zeroPaddedTallyGenerationState = (
    state: PaddedTallyGenerationState,
): void => {
    state.verifiedPreparationRoot.fill(0);
    state.targetIdentity.fill(0);
    state.sourceBodyIdentities.fill(0);
    state.allocationNonce.fill(0);
    if (state.phase === allocatedPaddedTallyGenerationPhase) {
        state.checkpointKey.fill(0);
        state.checkpoint.fill(0);
        return;
    }
    state.chunk.fill(0);
    state.chunkIdentity.fill(0);
    if (state.phase === retainedPaddedTallyChunkPhase) {
        state.checkpointKey.fill(0);
        state.nextCheckpoint.fill(0);
        return;
    }
    state.manifest.fill(0);
    state.manifestIdentity.fill(0);
    state.activationSignature.fill(0);
};

const requireCommonEvaluationState = (
    state: PaddedTallyEvaluationState,
    plan: PaddedTallyPlan,
): void => {
    requireExactLength(
        state.targetIdentity,
        identityByteLength,
        'evaluation target identity',
    );
    requireExactLength(
        state.activationInventoryDigest,
        digestByteLength,
        'activation inventory digest',
    );
    if (
        state.topCount !== plan.topCount ||
        state.chunkCount !== plan.chunks.length ||
        state.chunkCount < 1
    ) {
        throw new DurableStateError(
            'CorruptState',
            'The retained tally evaluation has invalid common fields.',
        );
    }
};

export const validatePaddedTallyEvaluationState = (
    state: PaddedTallyEvaluationState,
    plan: PaddedTallyPlan,
): void => {
    requireCommonEvaluationState(state, plan);
    if (state.phase === initializedPaddedTallyEvaluationPhase) {
        requireCheckpointKey(state.checkpointKey);
        if (state.generation !== 1n || state.checkpoint.byteLength === 0) {
            throw new DurableStateError(
                'CorruptState',
                'The retained tally evaluation initialization is invalid.',
            );
        }
        return;
    }
    requireExactLength(
        state.lastChunkSetDigest,
        digestByteLength,
        'last chunk-set digest',
    );
    if (state.generation !== BigInt(state.lastChunkOrdinal) + 2n) {
        throw new DurableStateError(
            'CorruptState',
            'The retained tally evaluation generation is inconsistent.',
        );
    }
    if (state.phase === pendingPaddedTallyEvaluationPhase) {
        requireCheckpointKey(state.checkpointKey);
        if (
            state.lastChunkOrdinal + 1 >= state.chunkCount ||
            state.checkpoint.byteLength === 0
        ) {
            throw new DurableStateError(
                'CorruptState',
                'The retained pending tally evaluation is invalid.',
            );
        }
        return;
    }
    if (state.lastChunkOrdinal + 1 !== state.chunkCount) {
        throw new DurableStateError(
            'CorruptState',
            'The retained tally terminal has the wrong final ordinal.',
        );
    }
    requireExactLength(
        state.batchIdentity,
        identityByteLength,
        'batch identity',
    );
    requireExactLength(
        state.terminalIdentity,
        identityByteLength,
        'terminal identity',
    );
    requireExactLength(
        state.outputSchemaIdentity,
        identityByteLength,
        'output schema identity',
    );
    if (
        state.terminalBody.byteLength === 0 ||
        state.terminalBody.byteLength > maximumTerminalBodyByteLength ||
        state.acceptedBallotAuthorshipBitmap < 0 ||
        state.acceptedBallotAuthorshipBitmap >=
            1 << completionProfileParticipantCount
    ) {
        throw new DurableStateError(
            'CorruptState',
            'The retained tally terminal fields are invalid.',
        );
    }
    if (state.orderedOptionPositions === undefined) return;
    if (
        state.orderedOptionPositions.length !== state.topCount ||
        new Set(state.orderedOptionPositions).size !== state.topCount ||
        state.orderedOptionPositions.some(
            (position) =>
                !Number.isSafeInteger(position) ||
                position < 0 ||
                position >= completionProfileParticipantCount,
        )
    ) {
        throw new DurableStateError(
            'CorruptState',
            'The retained tally result positions are invalid.',
        );
    }
};

const evaluationCommonByteLength =
    1 + 1 + 8 + identityByteLength + 2 + 2 + digestByteLength;

const writeEvaluationCommon = (
    writer: StateWriter,
    state: PaddedTallyEvaluationState,
): void => {
    writer.writeU8(stateVersion);
    writer.writeU8(state.phase);
    writer.writeU64(state.generation);
    writer.writeFixed(state.targetIdentity);
    writer.writeU16(state.topCount);
    writer.writeU16(state.chunkCount);
    writer.writeFixed(state.activationInventoryDigest);
};

export const encodePaddedTallyEvaluationState = (
    state: PaddedTallyEvaluationState,
    plan: PaddedTallyPlan,
): Uint8Array => {
    validatePaddedTallyEvaluationState(state, plan);
    if (state.phase === initializedPaddedTallyEvaluationPhase) {
        const writer = new StateWriter(
            evaluationCommonByteLength +
                paddedTallyCheckpointKeyByteLength +
                4 +
                state.checkpoint.byteLength,
        );
        writeEvaluationCommon(writer, state);
        writer.writeFixed(state.checkpointKey);
        writer.writeVariable(state.checkpoint);
        return writer.finish();
    }
    if (state.phase === pendingPaddedTallyEvaluationPhase) {
        const writer = new StateWriter(
            evaluationCommonByteLength +
                4 +
                digestByteLength +
                paddedTallyCheckpointKeyByteLength +
                4 +
                state.checkpoint.byteLength,
        );
        writeEvaluationCommon(writer, state);
        writer.writeU32(state.lastChunkOrdinal);
        writer.writeFixed(state.lastChunkSetDigest);
        writer.writeFixed(state.checkpointKey);
        writer.writeVariable(state.checkpoint);
        return writer.finish();
    }
    const positions = state.orderedOptionPositions ?? [];
    const writer = new StateWriter(
        evaluationCommonByteLength +
            4 +
            digestByteLength +
            identityByteLength +
            4 +
            state.terminalBody.byteLength +
            2 * identityByteLength +
            2 +
            1 +
            2 +
            2 * positions.length,
    );
    writeEvaluationCommon(writer, state);
    writer.writeU32(state.lastChunkOrdinal);
    writer.writeFixed(state.lastChunkSetDigest);
    writer.writeFixed(state.batchIdentity);
    writer.writeVariable(state.terminalBody);
    writer.writeFixed(state.terminalIdentity);
    writer.writeFixed(state.outputSchemaIdentity);
    writer.writeU16(state.acceptedBallotAuthorshipBitmap);
    writer.writeU8(state.orderedOptionPositions === undefined ? 2 : 1);
    writer.writeU16(positions.length);
    for (const position of positions) writer.writeU16(position);
    return writer.finish();
};

export const decodePaddedTallyEvaluationState = (
    bytes: Uint8Array,
    plan: PaddedTallyPlan,
): PaddedTallyEvaluationState => {
    const reader = new StateReader(bytes);
    if (reader.readU8() !== stateVersion) {
        throw new DurableStateError(
            'CorruptState',
            'The retained tally evaluation has the wrong version.',
        );
    }
    const phase = reader.readU8();
    const common = {
        generation: reader.readU64(),
        targetIdentity: reader.readFixed(identityByteLength),
        topCount: reader.readU16(),
        chunkCount: reader.readU16(),
        activationInventoryDigest: reader.readFixed(digestByteLength),
    };
    let state: PaddedTallyEvaluationState;
    if (phase === initializedPaddedTallyEvaluationPhase) {
        state = {
            ...common,
            phase,
            checkpointKey: reader.readFixed(paddedTallyCheckpointKeyByteLength),
            checkpoint: reader.readVariable(
                maximumFoundationCopiedBufferByteLength,
            ),
        };
    } else if (phase === pendingPaddedTallyEvaluationPhase) {
        state = {
            ...common,
            phase,
            lastChunkOrdinal: reader.readU32(),
            lastChunkSetDigest: reader.readFixed(digestByteLength),
            checkpointKey: reader.readFixed(paddedTallyCheckpointKeyByteLength),
            checkpoint: reader.readVariable(
                maximumFoundationCopiedBufferByteLength,
            ),
        };
    } else if (phase === completedPaddedTallyEvaluationPhase) {
        const lastChunkOrdinal = reader.readU32();
        const lastChunkSetDigest = reader.readFixed(digestByteLength);
        const batchIdentity = reader.readFixed(identityByteLength);
        const terminalBody = reader.readVariable(maximumTerminalBodyByteLength);
        const terminalIdentity = reader.readFixed(identityByteLength);
        const outputSchemaIdentity = reader.readFixed(identityByteLength);
        const acceptedBallotAuthorshipBitmap = reader.readU16();
        const resultKind = reader.readU8();
        const resultCount = reader.readU16();
        if (
            (resultKind !== 1 && resultKind !== 2) ||
            resultCount > completionProfileParticipantCount
        ) {
            throw new DurableStateError(
                'CorruptState',
                'The retained tally terminal kind is invalid.',
            );
        }
        const positions = Array.from({ length: resultCount }, () =>
            reader.readU16(),
        );
        if (resultKind === 2 && resultCount !== 0) {
            throw new DurableStateError(
                'CorruptState',
                'The retained no-result terminal contains positions.',
            );
        }
        state = {
            ...common,
            phase,
            lastChunkOrdinal,
            lastChunkSetDigest,
            batchIdentity,
            terminalBody,
            terminalIdentity,
            outputSchemaIdentity,
            acceptedBallotAuthorshipBitmap,
            orderedOptionPositions: resultKind === 1 ? positions : undefined,
        };
    } else {
        throw new DurableStateError(
            'CorruptState',
            'The retained tally evaluation has an invalid phase.',
        );
    }
    reader.finish();
    try {
        validatePaddedTallyEvaluationState(state, plan);
        return state;
    } catch (error) {
        zeroPaddedTallyEvaluationState(state);
        throw error;
    }
};

export const zeroPaddedTallyEvaluationState = (
    state: PaddedTallyEvaluationState,
): void => {
    state.targetIdentity.fill(0);
    state.activationInventoryDigest.fill(0);
    if (state.phase === initializedPaddedTallyEvaluationPhase) {
        state.checkpointKey.fill(0);
        state.checkpoint.fill(0);
        return;
    }
    state.lastChunkSetDigest.fill(0);
    if (state.phase === pendingPaddedTallyEvaluationPhase) {
        state.checkpointKey.fill(0);
        state.checkpoint.fill(0);
        return;
    }
    state.batchIdentity.fill(0);
    state.terminalBody.fill(0);
    state.terminalIdentity.fill(0);
    state.outputSchemaIdentity.fill(0);
};
