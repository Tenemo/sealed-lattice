import { describe, expect, it } from 'vitest';

import type { PaddedTallyPlan } from '../../src/padded-tally-runtime.js';
import {
    allocatedPaddedTallyGenerationPhase,
    completedPaddedTallyEvaluationPhase,
    completedPaddedTallyGenerationPhase,
    decodePaddedTallyEvaluationState,
    decodePaddedTallyGenerationState,
    encodePaddedTallyEvaluationState,
    encodePaddedTallyGenerationState,
    initializedPaddedTallyEvaluationPhase,
    pendingPaddedTallyEvaluationPhase,
    retainedPaddedTallyChunkPhase,
    zeroPaddedTallyEvaluationState,
    zeroPaddedTallyGenerationState,
    type PaddedTallyEvaluationState,
    type PaddedTallyGenerationState,
} from '../../src/padded-tally-worker-state.js';
import { actionSignatureCarrierByteLength } from '../../src/preparation-parent-runtime.js';

const plan: PaddedTallyPlan = {
    participantCount: 10,
    optionCount: 10,
    topCount: 1,
    inputWireCount: 410,
    operationCount: 1,
    constantCount: 0,
    linearCount: 0,
    conjunctionCount: 1,
    negationCount: 0,
    outputCount: 15,
    wireCount: 411,
    logicalPayloadByteLength: 13,
    labelEntropyByteLength: 81,
    manifestByteLength: 11,
    maximumLiveWireCount: 4,
    chunks: [
        {
            chunkByteLength: 7,
            labelEntropyByteLength: 81,
            liveWireCountAfterChunk: 1,
        },
        {
            chunkByteLength: 9,
            labelEntropyByteLength: 0,
            liveWireCountAfterChunk: 0,
        },
    ],
};

const filled = (length: number, value: number): Uint8Array =>
    new Uint8Array(length).fill(value);

const generationCommon = {
    preparationAttempt: 7,
    verifiedPreparationRoot: filled(64, 0x11),
    targetIdentity: filled(64, 0x22),
    sourceBodyIdentities: filled(640, 0x33),
    topCount: 1,
    chunkCount: 2,
    allocationNonce: filled(32, 0x44),
} as const;

const evaluationCommon = {
    targetIdentity: filled(64, 0x22),
    topCount: 1,
    chunkCount: 2,
    activationInventoryDigest: filled(32, 0x55),
} as const;

const expectAllZero = (...values: readonly Uint8Array[]): void => {
    for (const value of values) {
        expect(value.every((byte) => byte === 0)).toBe(true);
    }
};

describe('padded tally durable state codec', () => {
    it('round-trips every generation phase and retires checkpoint secrets', () => {
        const states: PaddedTallyGenerationState[] = [
            {
                ...generationCommon,
                phase: allocatedPaddedTallyGenerationPhase,
                generation: 1n,
                checkpointKey: filled(32, 0xa1),
                checkpoint: filled(17, 0xa2),
            },
            {
                ...generationCommon,
                phase: retainedPaddedTallyChunkPhase,
                generation: 2n,
                chunkOrdinal: 0,
                chunk: filled(7, 0xb1),
                chunkIdentity: filled(64, 0xb2),
                checkpointKey: filled(32, 0xb3),
                nextCheckpoint: filled(19, 0xb4),
            },
            {
                ...generationCommon,
                phase: completedPaddedTallyGenerationPhase,
                generation: 3n,
                chunkOrdinal: 1,
                chunk: filled(9, 0xc1),
                chunkIdentity: filled(64, 0xc2),
                manifest: filled(11, 0xc3),
                manifestIdentity: filled(64, 0xc4),
                activationSignature: filled(
                    actionSignatureCarrierByteLength,
                    0xc5,
                ),
            },
        ];
        for (const state of states) {
            const decoded = decodePaddedTallyGenerationState(
                encodePaddedTallyGenerationState(state, plan),
                plan,
            );
            expect(decoded).toEqual(state);
            zeroPaddedTallyGenerationState(decoded);
            expectAllZero(
                decoded.verifiedPreparationRoot,
                decoded.targetIdentity,
                decoded.sourceBodyIdentities,
                decoded.allocationNonce,
            );
            if (decoded.phase === allocatedPaddedTallyGenerationPhase) {
                expectAllZero(decoded.checkpointKey, decoded.checkpoint);
            } else if (decoded.phase === retainedPaddedTallyChunkPhase) {
                expectAllZero(
                    decoded.chunk,
                    decoded.chunkIdentity,
                    decoded.checkpointKey,
                    decoded.nextCheckpoint,
                );
            } else {
                expectAllZero(
                    decoded.chunk,
                    decoded.chunkIdentity,
                    decoded.manifest,
                    decoded.manifestIdentity,
                    decoded.activationSignature,
                );
            }
        }
    });

    it('round-trips pending and terminal evaluation without retaining keys', () => {
        const states: PaddedTallyEvaluationState[] = [
            {
                ...evaluationCommon,
                phase: initializedPaddedTallyEvaluationPhase,
                generation: 1n,
                checkpointKey: filled(32, 0xd1),
                checkpoint: filled(23, 0xd2),
            },
            {
                ...evaluationCommon,
                phase: pendingPaddedTallyEvaluationPhase,
                generation: 2n,
                lastChunkOrdinal: 0,
                lastChunkSetDigest: filled(32, 0xe1),
                checkpointKey: filled(32, 0xe2),
                checkpoint: filled(29, 0xe3),
            },
            {
                ...evaluationCommon,
                phase: completedPaddedTallyEvaluationPhase,
                generation: 3n,
                lastChunkOrdinal: 1,
                lastChunkSetDigest: filled(32, 0xf1),
                batchIdentity: filled(64, 0xf2),
                terminalBody: filled(97, 0xf3),
                terminalIdentity: filled(64, 0xf4),
                outputSchemaIdentity: filled(64, 0xf5),
                acceptedBallotAuthorshipBitmap: 0x155,
                orderedOptionPositions: [3],
            },
        ];
        for (const state of states) {
            const decoded = decodePaddedTallyEvaluationState(
                encodePaddedTallyEvaluationState(state, plan),
                plan,
            );
            expect(decoded).toEqual(state);
            zeroPaddedTallyEvaluationState(decoded);
            expectAllZero(
                decoded.targetIdentity,
                decoded.activationInventoryDigest,
            );
            if (decoded.phase === initializedPaddedTallyEvaluationPhase) {
                expectAllZero(decoded.checkpointKey, decoded.checkpoint);
            } else if (decoded.phase === pendingPaddedTallyEvaluationPhase) {
                expectAllZero(
                    decoded.lastChunkSetDigest,
                    decoded.checkpointKey,
                    decoded.checkpoint,
                );
            } else {
                expectAllZero(
                    decoded.lastChunkSetDigest,
                    decoded.batchIdentity,
                    decoded.terminalBody,
                    decoded.terminalIdentity,
                    decoded.outputSchemaIdentity,
                );
            }
        }
    });

    it('refuses version, generation, key, and trailing-byte mutations', () => {
        const state: PaddedTallyGenerationState = {
            ...generationCommon,
            phase: allocatedPaddedTallyGenerationPhase,
            generation: 1n,
            checkpointKey: filled(32, 0x61),
            checkpoint: filled(17, 0x62),
        };
        const encoded = encodePaddedTallyGenerationState(state, plan);
        const wrongVersion = Uint8Array.from(encoded);
        wrongVersion[0] ^= 1;
        expect(() =>
            decodePaddedTallyGenerationState(wrongVersion, plan),
        ).toThrow();
        expect(() =>
            decodePaddedTallyGenerationState(
                Uint8Array.from([...encoded, 0]),
                plan,
            ),
        ).toThrow();
        expect(() =>
            encodePaddedTallyGenerationState(
                { ...state, generation: 2n },
                plan,
            ),
        ).toThrow();
        expect(() =>
            encodePaddedTallyGenerationState(
                { ...state, checkpointKey: new Uint8Array(32) },
                plan,
            ),
        ).toThrow();
    });
});
