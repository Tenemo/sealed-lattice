import { actionSignatureByteLength } from './action-signature-runtime.js';
import {
    ConstructionCommandWriter,
    executeConstructionCommand,
    requireExactConstructionBytes,
} from './construction-kernel-command-runtime.js';
import {
    completionProfileFinalityQuorum,
    finalityTargetBodyByteLength,
    type FinalitySignatureCarrier,
} from './finality-runtime.js';
import type { ConstructionKernelCommandRuntime } from './foundation-kernel/kernel-runtime.js';
import {
    preparationContributionOpeningVectorByteLength,
    preparationPairwiseMasterVectorByteLength,
    preparationPlaintextByteLength,
} from './preparation-material-runtime.js';
import {
    actionSignatureCarrierByteLength,
    preparationParentBodyByteLength,
} from './preparation-parent-runtime.js';
import { completionRosterByteLength } from './roster-runtime.js';
import {
    abstentionSourceBodyByteLength,
    submittedSourceBodyByteLength,
} from './source-runtime.js';

const compilePlanCommand = 42;
const initializeGenerationCommand = 43;
const generateNextChunkCommand = 44;
const initializeEvaluationCommand = 45;
const evaluateNextChunkCommand = 46;
const encodeActivationSignatureCommand = 47;

const completionProfileParticipantCount = 10;
const completionProfileOptionCount = 10;
const identityByteLength = 64;
const checkpointKeyByteLength = 32;
const allocationNonceByteLength = 32;
const labelByteLength = 40;
const labelPairEntropyByteLength = 2 * labelByteLength + 1;
const maximumRandomRequestByteLength = 65_536;
const maximumChunkByteLength = 480_000;
const resultMagic = new TextEncoder().encode('SLPR');
const resultVersion = 1;
const resultKindResult = 1;
const resultKindNoResult = 2;

export const paddedTallyCheckpointKeyByteLength = checkpointKeyByteLength;
export const paddedTallyAllocationNonceByteLength = allocationNonceByteLength;
export const paddedTallyMaximumChunkByteLength = maximumChunkByteLength;

type PaddedTallyFinalityCertificate = Readonly<{
    targetBody: Uint8Array;
    canonicalRosterBytes: Uint8Array;
    signatures: readonly FinalitySignatureCarrier[];
}>;

type PaddedTallySourceCarrier = Readonly<{
    body: Uint8Array;
    signature: Uint8Array;
}>;

type PaddedTallyPreparationInput = Readonly<{
    parents: readonly Readonly<{
        body: Uint8Array;
        signature: Uint8Array;
    }>[];
    ownContributionOpenings: Uint8Array;
    ownPairwiseMasters: Uint8Array;
    remotePlaintexts: readonly Uint8Array[];
}>;

type PaddedTallyChunkPlan = Readonly<{
    chunkByteLength: number;
    labelEntropyByteLength: number;
    liveWireCountAfterChunk: number;
}>;

export type PaddedTallyPlan = Readonly<{
    participantCount: number;
    optionCount: number;
    topCount: number;
    inputWireCount: number;
    operationCount: number;
    constantCount: number;
    linearCount: number;
    conjunctionCount: number;
    negationCount: number;
    outputCount: number;
    wireCount: number;
    logicalPayloadByteLength: number;
    labelEntropyByteLength: number;
    manifestByteLength: number;
    maximumLiveWireCount: number;
    chunks: readonly PaddedTallyChunkPlan[];
}>;

declare const generationCheckpointBrand: unique symbol;
export type PaddedTallyGenerationCheckpoint = Uint8Array & {
    readonly [generationCheckpointBrand]: true;
};

declare const evaluationCheckpointBrand: unique symbol;
export type PaddedTallyEvaluationCheckpoint = Uint8Array & {
    readonly [evaluationCheckpointBrand]: true;
};

type GeneratedPaddedTallyChunk = Readonly<{
    chunkOrdinal: number;
    chunk: Uint8Array;
    chunkIdentity: Uint8Array;
}> &
    (
        | Readonly<{
              status: 'pending';
              nextCheckpoint: PaddedTallyGenerationCheckpoint;
          }>
        | Readonly<{
              status: 'complete';
              manifest: Uint8Array;
              manifestIdentity: Uint8Array;
          }>
    );

const verifiedTerminalBrand: unique symbol = Symbol(
    'verified-padded-tally-terminal',
);
type VerifiedPaddedTallyTerminal = Readonly<{
    [verifiedTerminalBrand]: true;
    batchIdentity: Uint8Array;
    body: Uint8Array;
    bodyIdentity: Uint8Array;
    targetIdentity: Uint8Array;
    outputSchemaIdentity: Uint8Array;
    topCount: number;
    acceptedBallotAuthorship: readonly boolean[];
    orderedOptionPositions: readonly number[] | undefined;
}>;

type EvaluatedPaddedTallyChunk = Readonly<{
    chunkOrdinal: number;
}> &
    (
        | Readonly<{
              status: 'pending';
              nextCheckpoint: PaddedTallyEvaluationCheckpoint;
          }>
        | Readonly<{
              status: 'complete';
              terminal: VerifiedPaddedTallyTerminal;
          }>
    );

export type PaddedTallyRuntime = Readonly<{
    compilePlan(topCount: number): PaddedTallyPlan;
    initializeGeneration(
        certificate: PaddedTallyFinalityCertificate,
        participantPosition: number,
        allocationNonce: Uint8Array,
        checkpointKey: Uint8Array,
        sources: readonly PaddedTallySourceCarrier[],
        preparation: PaddedTallyPreparationInput,
    ): PaddedTallyGenerationCheckpoint;
    generateNextChunk(
        plan: PaddedTallyPlan,
        expectedChunkOrdinal: number,
        checkpointKey: Uint8Array,
        checkpoint: PaddedTallyGenerationCheckpoint,
        labelEntropy: Uint8Array,
    ): GeneratedPaddedTallyChunk;
    encodeActivationSignature(
        participantPosition: number,
        manifestIdentity: Uint8Array,
        signature: Uint8Array,
    ): Uint8Array;
    initializeEvaluation(
        certificate: PaddedTallyFinalityCertificate,
        checkpointKey: Uint8Array,
        manifests: readonly Uint8Array[],
        signatures: readonly Uint8Array[],
        plan: PaddedTallyPlan,
    ): PaddedTallyEvaluationCheckpoint;
    evaluateNextChunk(
        plan: PaddedTallyPlan,
        expectedChunkOrdinal: number,
        checkpointKey: Uint8Array,
        checkpoint: PaddedTallyEvaluationCheckpoint,
        participantPosition: number,
        chunk: Uint8Array,
    ): EvaluatedPaddedTallyChunk | undefined;
}>;

type RandomFill = (bytes: Uint8Array) => void;

const defaultRandomFill: RandomFill = (bytes) => {
    const browserCrypto = globalThis.crypto;
    if (browserCrypto === undefined) {
        throw new Error('A cryptographic random source is unavailable.');
    }
    browserCrypto.getRandomValues(bytes as Uint8Array<ArrayBuffer>);
};

const fillIndependentRandomBytes = (
    bytes: Uint8Array,
    fill: RandomFill,
): void => {
    for (
        let offset = 0;
        offset < bytes.byteLength;
        offset += maximumRandomRequestByteLength
    ) {
        fill(
            bytes.subarray(
                offset,
                Math.min(
                    bytes.byteLength,
                    offset + maximumRandomRequestByteLength,
                ),
            ),
        );
    }
};

export const drawPaddedTallyIndependentBytes = (
    byteLength: number,
    fill: RandomFill = defaultRandomFill,
): Uint8Array => {
    if (!Number.isSafeInteger(byteLength) || byteLength <= 0) {
        throw new RangeError('byteLength must be a positive safe integer.');
    }
    const bytes = new Uint8Array(byteLength);
    fillIndependentRandomBytes(bytes, fill);
    return bytes;
};

const equalSlices = (
    bytes: Uint8Array,
    firstOffset: number,
    secondOffset: number,
    length: number,
): boolean => {
    let difference = 0;
    for (let index = 0; index < length; index += 1) {
        difference |=
            (bytes[firstOffset + index] ?? 0) ^
            (bytes[secondOffset + index] ?? 0);
    }
    return difference === 0;
};

export const drawPaddedTallyLabelEntropy = (
    byteLength: number,
    fill: RandomFill = defaultRandomFill,
): Uint8Array => {
    if (
        !Number.isSafeInteger(byteLength) ||
        byteLength <= 0 ||
        byteLength % labelPairEntropyByteLength !== 0
    ) {
        throw new RangeError(
            'byteLength must contain complete padded-tally label pairs.',
        );
    }
    const entropy = drawPaddedTallyIndependentBytes(byteLength, fill);
    for (
        let offset = 0;
        offset < entropy.byteLength;
        offset += labelPairEntropyByteLength
    ) {
        const secondLabel = entropy.subarray(
            offset + labelByteLength,
            offset + 2 * labelByteLength,
        );
        while (
            equalSlices(
                entropy,
                offset,
                offset + labelByteLength,
                labelByteLength,
            )
        ) {
            fillIndependentRandomBytes(secondLabel, fill);
        }
        entropy[offset + 2 * labelByteLength] =
            (entropy[offset + 2 * labelByteLength] ?? 0) & 1;
    }
    return entropy;
};

const requireUnsigned16 = (value: number, name: string): void => {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) {
        throw new RangeError(`${name} must be an unsigned 16-bit integer.`);
    }
};

const requirePosition = (value: number, name: string): void => {
    requireUnsigned16(value, name);
    if (value >= completionProfileParticipantCount) {
        throw new RangeError(`${name} is not a completion-profile position.`);
    }
};

const requireTopCount = (topCount: number): void => {
    requireUnsigned16(topCount, 'topCount');
    if (topCount === 0 || topCount > completionProfileOptionCount) {
        throw new RangeError(
            'topCount is not admitted by the completion profile.',
        );
    }
};

const requireCheckpointKey = (key: Uint8Array): void => {
    requireExactConstructionBytes(
        key,
        checkpointKeyByteLength,
        'checkpointKey',
    );
    if (key.every((value) => value === 0)) {
        throw new RangeError('checkpointKey must not be the all-zero key.');
    }
};

const writeCertificate = (
    request: ConstructionCommandWriter,
    certificate: PaddedTallyFinalityCertificate,
): void => {
    requireExactConstructionBytes(
        certificate.targetBody,
        finalityTargetBodyByteLength,
        'targetBody',
    );
    requireExactConstructionBytes(
        certificate.canonicalRosterBytes,
        completionRosterByteLength,
        'canonicalRosterBytes',
    );
    if (
        certificate.signatures.length < completionProfileFinalityQuorum ||
        certificate.signatures.length > completionProfileParticipantCount
    ) {
        throw new RangeError(
            'signatures must contain a completion-profile quorum.',
        );
    }
    request.writeU16(completionProfileParticipantCount);
    request.writeBytes(certificate.targetBody);
    request.writeBytes(certificate.canonicalRosterBytes);
    request.writeU16(certificate.signatures.length);
    for (const entry of certificate.signatures) {
        requirePosition(entry.signerPosition, 'signerPosition');
        requireExactConstructionBytes(
            entry.signature,
            actionSignatureCarrierByteLength,
            'finalitySignatureCarrier',
        );
        request.writeU16(entry.signerPosition);
        request.writeBytes(entry.signature);
    }
};

const validatePlan = (plan: PaddedTallyPlan): void => {
    requireTopCount(plan.topCount);
    if (
        plan.participantCount !== completionProfileParticipantCount ||
        plan.optionCount !== completionProfileOptionCount ||
        plan.inputWireCount !== 410 ||
        plan.outputCount !==
            completionProfileParticipantCount + 1 + 4 * plan.topCount ||
        plan.chunks.length === 0 ||
        plan.chunks.some(
            (chunk) =>
                chunk.chunkByteLength <= 0 ||
                chunk.chunkByteLength > maximumChunkByteLength ||
                chunk.labelEntropyByteLength <= 0 ||
                chunk.labelEntropyByteLength % labelPairEntropyByteLength !== 0,
        ) ||
        plan.chunks[plan.chunks.length - 1]?.liveWireCountAfterChunk !== 0 ||
        plan.chunks.reduce(
            (total, chunk) => total + chunk.labelEntropyByteLength,
            0,
        ) !== plan.labelEntropyByteLength
    ) {
        throw new Error(
            'The construction kernel returned an invalid padded-tally plan.',
        );
    }
};

const requireCompleteSources = (
    sources: readonly PaddedTallySourceCarrier[],
): void => {
    if (sources.length !== completionProfileParticipantCount) {
        throw new RangeError('sources must contain the complete roster.');
    }
    for (const [position, source] of sources.entries()) {
        if (
            source.body.byteLength !== abstentionSourceBodyByteLength &&
            source.body.byteLength !== submittedSourceBodyByteLength
        ) {
            throw new TypeError(
                `sources[${String(position)}].body has an unsupported length.`,
            );
        }
        requireExactConstructionBytes(
            source.signature,
            actionSignatureCarrierByteLength,
            `sources[${String(position)}].signature`,
        );
    }
};

const requirePreparation = (preparation: PaddedTallyPreparationInput): void => {
    if (preparation.parents.length !== completionProfileParticipantCount) {
        throw new RangeError('parents must contain the complete roster.');
    }
    for (const [position, parent] of preparation.parents.entries()) {
        requireExactConstructionBytes(
            parent.body,
            preparationParentBodyByteLength(completionProfileParticipantCount),
            `parents[${String(position)}].body`,
        );
        requireExactConstructionBytes(
            parent.signature,
            actionSignatureCarrierByteLength,
            `parents[${String(position)}].signature`,
        );
    }
    requireExactConstructionBytes(
        preparation.ownContributionOpenings,
        preparationContributionOpeningVectorByteLength,
        'ownContributionOpenings',
    );
    requireExactConstructionBytes(
        preparation.ownPairwiseMasters,
        preparationPairwiseMasterVectorByteLength,
        'ownPairwiseMasters',
    );
    if (
        preparation.remotePlaintexts.length !==
        completionProfileParticipantCount - 1
    ) {
        throw new RangeError(
            'remotePlaintexts must contain every remote sender in roster order.',
        );
    }
    for (const plaintext of preparation.remotePlaintexts) {
        requireExactConstructionBytes(
            plaintext,
            preparationPlaintextByteLength,
            'remotePlaintext',
        );
    }
};

const decodeVerifiedTerminal = (
    batchIdentity: Uint8Array,
    body: Uint8Array,
    bodyIdentity: Uint8Array,
    expectedTopCount: number,
): VerifiedPaddedTallyTerminal => {
    const minimumLength =
        4 +
        2 +
        2 * identityByteLength +
        2 +
        1 +
        completionProfileParticipantCount +
        2;
    if (body.byteLength < minimumLength) {
        throw new Error(
            'The construction kernel returned a truncated tally terminal.',
        );
    }
    const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
    let offset = 0;
    if (resultMagic.some((value, index) => body[index] !== value)) {
        throw new Error(
            'The construction kernel returned the wrong tally terminal magic.',
        );
    }
    offset += resultMagic.byteLength;
    if (view.getUint16(offset, true) !== resultVersion) {
        throw new Error(
            'The construction kernel returned the wrong tally terminal version.',
        );
    }
    offset += 2;
    const targetIdentity = Uint8Array.from(
        body.subarray(offset, offset + identityByteLength),
    );
    offset += identityByteLength;
    const outputSchemaIdentity = Uint8Array.from(
        body.subarray(offset, offset + identityByteLength),
    );
    offset += identityByteLength;
    const topCount = view.getUint16(offset, true);
    offset += 2;
    if (topCount !== expectedTopCount) {
        throw new Error(
            'The construction kernel returned the wrong tally terminal width.',
        );
    }
    const kind = body[offset] ?? 0;
    offset += 1;
    const acceptedBallotAuthorship: boolean[] = [];
    for (
        let position = 0;
        position < completionProfileParticipantCount;
        position += 1
    ) {
        const value = body[offset] ?? 2;
        offset += 1;
        if (value !== 0 && value !== 1) {
            throw new Error(
                'The construction kernel returned noncanonical authorship.',
            );
        }
        acceptedBallotAuthorship.push(value === 1);
    }
    const resultCount = view.getUint16(offset, true);
    offset += 2;
    const expectedLength = offset + 2 * resultCount;
    if (body.byteLength !== expectedLength) {
        throw new Error(
            'The construction kernel returned a malformed tally terminal length.',
        );
    }
    const positions: number[] = [];
    const seenPositions = new Set<number>();
    for (let index = 0; index < resultCount; index += 1) {
        const position = view.getUint16(offset, true);
        offset += 2;
        if (
            position >= completionProfileOptionCount ||
            seenPositions.has(position)
        ) {
            throw new Error(
                'The construction kernel returned an invalid option position.',
            );
        }
        seenPositions.add(position);
        positions.push(position);
    }
    let orderedOptionPositions: readonly number[] | undefined;
    if (kind === resultKindResult && resultCount === topCount) {
        orderedOptionPositions = positions;
    } else if (kind === resultKindNoResult && resultCount === 0) {
        orderedOptionPositions = undefined;
    } else {
        throw new Error(
            'The construction kernel returned an invalid tally terminal kind.',
        );
    }
    return {
        [verifiedTerminalBrand]: true,
        batchIdentity,
        body,
        bodyIdentity,
        targetIdentity,
        outputSchemaIdentity,
        topCount,
        acceptedBallotAuthorship,
        orderedOptionPositions,
    };
};

export const openPaddedTallyRuntime = (
    kernel: ConstructionKernelCommandRuntime,
): PaddedTallyRuntime => ({
    compilePlan: (topCount) => {
        requireTopCount(topCount);
        const request = new ConstructionCommandWriter();
        request.writeU8(compilePlanCommand);
        request.writeU16(topCount);
        return executeConstructionCommand(kernel, request, (reader) => {
            const plan: PaddedTallyPlan = {
                participantCount: reader.readU16(),
                optionCount: reader.readU16(),
                topCount: reader.readU16(),
                inputWireCount: reader.readU32(),
                operationCount: reader.readU32(),
                constantCount: reader.readU32(),
                linearCount: reader.readU32(),
                conjunctionCount: reader.readU32(),
                negationCount: reader.readU32(),
                outputCount: reader.readU32(),
                wireCount: reader.readU32(),
                logicalPayloadByteLength: reader.readU32(),
                labelEntropyByteLength: reader.readU32(),
                manifestByteLength: reader.readU32(),
                maximumLiveWireCount: reader.readU32(),
                chunks: Array.from({ length: reader.readU16() }, () => ({
                    chunkByteLength: reader.readU32(),
                    labelEntropyByteLength: reader.readU32(),
                    liveWireCountAfterChunk: reader.readU32(),
                })),
            };
            if (plan.topCount !== topCount) {
                throw new Error(
                    'The construction kernel returned a different topCount.',
                );
            }
            validatePlan(plan);
            return plan;
        });
    },
    initializeGeneration: (
        certificate,
        participantPosition,
        allocationNonce,
        checkpointKey,
        sources,
        preparation,
    ) => {
        requirePosition(participantPosition, 'participantPosition');
        requireExactConstructionBytes(
            allocationNonce,
            allocationNonceByteLength,
            'allocationNonce',
        );
        requireCheckpointKey(checkpointKey);
        requireCompleteSources(sources);
        requirePreparation(preparation);
        const request = new ConstructionCommandWriter();
        request.writeU8(initializeGenerationCommand);
        writeCertificate(request, certificate);
        request.writeU16(participantPosition);
        request.writeBytes(allocationNonce);
        request.writeBytes(checkpointKey);
        for (const source of sources) {
            request.writeBytes(source.body);
            request.writeBytes(source.signature);
        }
        for (const parent of preparation.parents) {
            request.writeBytes(parent.body);
            request.writeBytes(parent.signature);
        }
        request.writeBytes(preparation.ownContributionOpenings);
        request.writeBytes(preparation.ownPairwiseMasters);
        for (const plaintext of preparation.remotePlaintexts) {
            request.writeBytes(plaintext);
        }
        return executeConstructionCommand(kernel, request, (reader) =>
            Uint8Array.from(reader.readBytes()),
        ) as PaddedTallyGenerationCheckpoint;
    },
    generateNextChunk: (
        plan,
        expectedChunkOrdinal,
        checkpointKey,
        checkpoint,
        labelEntropy,
    ) => {
        validatePlan(plan);
        const chunkPlan = plan.chunks[expectedChunkOrdinal];
        if (chunkPlan === undefined) {
            throw new RangeError('expectedChunkOrdinal is outside the plan.');
        }
        requireCheckpointKey(checkpointKey);
        requireExactConstructionBytes(
            labelEntropy,
            chunkPlan.labelEntropyByteLength,
            'labelEntropy',
        );
        const request = new ConstructionCommandWriter();
        request.writeU8(generateNextChunkCommand);
        request.writeBytes(checkpointKey);
        request.writeBytes(checkpoint);
        request.writeBytes(labelEntropy);
        return executeConstructionCommand(kernel, request, (reader) => {
            const chunkOrdinal = reader.readU32();
            if (chunkOrdinal !== expectedChunkOrdinal) {
                throw new Error(
                    'The generation checkpoint advanced out of order.',
                );
            }
            const chunk = Uint8Array.from(reader.readBytes());
            requireExactConstructionBytes(
                chunk,
                chunkPlan.chunkByteLength,
                'paddedTallyChunk',
            );
            const chunkIdentity = Uint8Array.from(
                reader.readFixed(identityByteLength),
            );
            const status = reader.readU8();
            if (status === 1 && expectedChunkOrdinal + 1 < plan.chunks.length) {
                return {
                    status: 'pending' as const,
                    chunkOrdinal,
                    chunk,
                    chunkIdentity,
                    nextCheckpoint: Uint8Array.from(
                        reader.readBytes(),
                    ) as PaddedTallyGenerationCheckpoint,
                };
            }
            if (
                status === 2 &&
                expectedChunkOrdinal + 1 === plan.chunks.length
            ) {
                const manifest = Uint8Array.from(reader.readBytes());
                requireExactConstructionBytes(
                    manifest,
                    plan.manifestByteLength,
                    'paddedTallyManifest',
                );
                return {
                    status: 'complete' as const,
                    chunkOrdinal,
                    chunk,
                    chunkIdentity,
                    manifest,
                    manifestIdentity: Uint8Array.from(
                        reader.readFixed(identityByteLength),
                    ),
                };
            }
            throw new Error(
                'The construction kernel returned an invalid generation state.',
            );
        });
    },
    encodeActivationSignature: (
        participantPosition,
        manifestIdentity,
        signature,
    ) => {
        requirePosition(participantPosition, 'participantPosition');
        requireExactConstructionBytes(
            manifestIdentity,
            identityByteLength,
            'manifestIdentity',
        );
        requireExactConstructionBytes(
            signature,
            actionSignatureByteLength,
            'actionSignature',
        );
        const request = new ConstructionCommandWriter();
        request.writeU8(encodeActivationSignatureCommand);
        request.writeU16(participantPosition);
        request.writeFixed(manifestIdentity);
        request.writeBytes(signature);
        return executeConstructionCommand(kernel, request, (reader) => {
            const carrier = Uint8Array.from(reader.readBytes());
            requireExactConstructionBytes(
                carrier,
                actionSignatureCarrierByteLength,
                'activationSignatureCarrier',
            );
            return carrier;
        });
    },
    initializeEvaluation: (
        certificate,
        checkpointKey,
        manifests,
        signatures,
        plan,
    ) => {
        validatePlan(plan);
        requireCheckpointKey(checkpointKey);
        if (
            manifests.length !== completionProfileParticipantCount ||
            signatures.length !== completionProfileParticipantCount
        ) {
            throw new RangeError(
                'manifests and signatures must contain the complete roster.',
            );
        }
        const request = new ConstructionCommandWriter();
        request.writeU8(initializeEvaluationCommand);
        writeCertificate(request, certificate);
        request.writeBytes(checkpointKey);
        for (
            let position = 0;
            position < completionProfileParticipantCount;
            position += 1
        ) {
            const manifest = manifests[position] ?? new Uint8Array();
            const signature = signatures[position] ?? new Uint8Array();
            requireExactConstructionBytes(
                manifest,
                plan.manifestByteLength,
                `manifests[${String(position)}]`,
            );
            requireExactConstructionBytes(
                signature,
                actionSignatureCarrierByteLength,
                `signatures[${String(position)}]`,
            );
            request.writeBytes(manifest);
            request.writeBytes(signature);
        }
        return executeConstructionCommand(kernel, request, (reader) =>
            Uint8Array.from(reader.readBytes()),
        ) as PaddedTallyEvaluationCheckpoint;
    },
    evaluateNextChunk: (
        plan,
        expectedChunkOrdinal,
        checkpointKey,
        checkpoint,
        participantPosition,
        chunk,
    ) => {
        validatePlan(plan);
        const chunkPlan = plan.chunks[expectedChunkOrdinal];
        if (chunkPlan === undefined) {
            throw new RangeError('expectedChunkOrdinal is outside the plan.');
        }
        requireCheckpointKey(checkpointKey);
        requirePosition(participantPosition, 'participantPosition');
        requireExactConstructionBytes(
            chunk,
            chunkPlan.chunkByteLength,
            'chunk',
        );
        const request = new ConstructionCommandWriter();
        request.writeU8(evaluateNextChunkCommand);
        request.writeBytes(checkpointKey);
        request.writeBytes(checkpoint);
        request.writeU16(participantPosition);
        request.writeBytes(chunk);
        return executeConstructionCommand(kernel, request, (reader) => {
            if (participantPosition + 1 < completionProfileParticipantCount) {
                return undefined;
            }
            const chunkOrdinal = reader.readU32();
            if (chunkOrdinal !== expectedChunkOrdinal) {
                throw new Error(
                    'The evaluation checkpoint advanced out of order.',
                );
            }
            const status = reader.readU8();
            if (status === 1 && expectedChunkOrdinal + 1 < plan.chunks.length) {
                return {
                    status: 'pending' as const,
                    chunkOrdinal,
                    nextCheckpoint: Uint8Array.from(
                        reader.readBytes(),
                    ) as PaddedTallyEvaluationCheckpoint,
                };
            }
            if (
                status === 2 &&
                expectedChunkOrdinal + 1 === plan.chunks.length
            ) {
                const batchIdentity = Uint8Array.from(
                    reader.readFixed(identityByteLength),
                );
                const body = Uint8Array.from(reader.readBytes());
                const bodyIdentity = Uint8Array.from(
                    reader.readFixed(identityByteLength),
                );
                return {
                    status: 'complete' as const,
                    chunkOrdinal,
                    terminal: decodeVerifiedTerminal(
                        batchIdentity,
                        body,
                        bodyIdentity,
                        plan.topCount,
                    ),
                };
            }
            throw new Error(
                'The construction kernel returned an invalid evaluation state.',
            );
        });
    },
});
