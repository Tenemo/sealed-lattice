import { BrowserActionStorageCustodyError } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    actionRandomnessCommandOutputByteLimit,
    maximumClosedWorkerCommandByteLength,
} from '#packages/wasm/src/action-randomness-command-byte-limits';
import { actionRandomnessCommandIdentifiers } from '#packages/wasm/src/action-randomness-command-identifiers';
import {
    decodeStructuredCommitmentWorkerResponse,
    structuredCommitmentModulusIndices,
    structuredCommitmentRowCount,
    structuredCommitmentWorkerResponseFormatIdentifier,
    structuredCommitmentWorkerResponseHeaderByteLength,
    structuredCommitmentWorkerResponseLimbHeaderByteLength,
    structuredCommitmentWorkerResponseProductionByteLength,
    structuredCommitmentWorkerResponseVersion,
} from '#packages/wasm/src/structured-commitment-worker-response';

const productionRingDegree = 32_768;
const sourceRnsLimbIndex = 2;
const shamirCoefficientIndex = 4;
const dataPrimes = Object.freeze([
    140_700_980_543_489, 140_546_359_361_537, 140_507_704_066_049,
]);
const limbByteLength =
    structuredCommitmentWorkerResponseLimbHeaderByteLength +
    structuredCommitmentRowCount * productionRingDegree * 8;
const productionResponseByteLength =
    structuredCommitmentWorkerResponseHeaderByteLength +
    structuredCommitmentModulusIndices.length * limbByteLength;

const encodeResponse = (): Uint8Array<ArrayBuffer> => {
    const bytes = new Uint8Array(productionResponseByteLength);
    const view = new DataView(bytes.buffer);
    view.setUint32(0, structuredCommitmentWorkerResponseFormatIdentifier, true);
    view.setUint32(4, structuredCommitmentWorkerResponseVersion, true);
    view.setUint32(8, sourceRnsLimbIndex, true);
    view.setBigUint64(12, BigInt(shamirCoefficientIndex), true);
    view.setUint32(20, productionRingDegree, true);
    view.setUint32(24, structuredCommitmentModulusIndices.length, true);
    view.setUint32(28, structuredCommitmentRowCount, true);
    let byteOffset = structuredCommitmentWorkerResponseHeaderByteLength;
    structuredCommitmentModulusIndices.forEach(
        (modulusIndex, commitmentLimbPosition) => {
            const modulus = dataPrimes[modulusIndex];
            if (modulus === undefined) {
                throw new Error('Missing selected data prime in test fixture.');
            }
            view.setUint32(byteOffset, modulusIndex, true);
            byteOffset +=
                structuredCommitmentWorkerResponseLimbHeaderByteLength;
            for (
                let rowIndex = 0;
                rowIndex < structuredCommitmentRowCount;
                rowIndex += 1
            ) {
                for (
                    let coefficientIndex = 0;
                    coefficientIndex < productionRingDegree;
                    coefficientIndex += 1
                ) {
                    const residue =
                        (commitmentLimbPosition * 1_000_003 +
                            rowIndex * 65_537 +
                            coefficientIndex * 17) %
                        modulus;
                    view.setBigUint64(byteOffset, BigInt(residue), true);
                    byteOffset += 8;
                }
            }
        },
    );
    if (byteOffset !== bytes.byteLength) {
        throw new Error('Structured-commitment test fixture length drifted.');
    }
    return bytes;
};

const decodeResponse = (bytes: Uint8Array) =>
    decodeStructuredCommitmentWorkerResponse({
        bytes,
        dataPrimes,
        expectedRingDegree: productionRingDegree,
        expectedShamirCoefficientIndex: shamirCoefficientIndex,
        expectedSourceRnsLimbIndex: sourceRnsLimbIndex,
    });

const expectMalformedResponse = (bytes: Uint8Array): void => {
    expect(() => decodeResponse(bytes)).toThrowError(
        BrowserActionStorageCustodyError,
    );
};

describe('Structured-commitment worker response', () => {
    it('uses the exact structured-commitment output bound only for its command', () => {
        expect(
            actionRandomnessCommandOutputByteLimit(
                actionRandomnessCommandIdentifiers.computeStructuredCommitment,
            ),
        ).toBe(structuredCommitmentWorkerResponseProductionByteLength);
        expect(structuredCommitmentWorkerResponseProductionByteLength).toBe(
            1_572_908,
        );
        expect(maximumClosedWorkerCommandByteLength).toBe(8_388_608);
        Object.values(actionRandomnessCommandIdentifiers)
            .filter(
                (command) =>
                    command !==
                    actionRandomnessCommandIdentifiers.computeStructuredCommitment,
            )
            .forEach((command) => {
                expect(actionRandomnessCommandOutputByteLimit(command)).toBe(
                    maximumClosedWorkerCommandByteLength,
                );
            });
        expect(actionRandomnessCommandOutputByteLimit(0xffff_ffff)).toBe(
            maximumClosedWorkerCommandByteLength,
        );
    });

    it('decodes the exact production-size binary frame without retaining framing fields', () => {
        const frame = encodeResponse();
        expect(frame).toHaveLength(1_572_908);
        expect(frame).toHaveLength(productionResponseByteLength);

        const padded = new Uint8Array(frame.byteLength + 11);
        padded.set(frame, 7);
        const computation = decodeResponse(
            padded.subarray(7, 7 + frame.byteLength),
        );
        expect(computation.commitment).toMatchObject({
            objectType: 'SetupCommitment',
            ringDegree: productionRingDegree,
            shamirCoefficientIndex,
            sourceRnsLimbIndex,
        });
        expect(computation.commitment.commitmentLimbs).toHaveLength(3);
        computation.commitment.commitmentLimbs.forEach((limb) => {
            expect(limb.rows).toHaveLength(structuredCommitmentRowCount);
            limb.rows.forEach((row) => {
                expect(row).toHaveLength(productionRingDegree);
            });
        });
        expect(computation.commitment.commitmentLimbs[0]?.rows[0]?.[0]).toBe(0);
        expect(
            computation.commitment.commitmentLimbs[2]?.rows[1]?.[
                productionRingDegree - 1
            ],
        ).toBe(2 * 1_000_003 + 65_537 + (productionRingDegree - 1) * 17);
    });

    it('rejects truncation and trailing bytes', () => {
        const frame = encodeResponse();
        expectMalformedResponse(frame.subarray(0, frame.byteLength - 1));
        const withTrailingByte = new Uint8Array(frame.byteLength + 1);
        withTrailingByte.set(frame);
        expectMalformedResponse(withTrailingByte);
    });

    it.each([
        {
            name: 'format identifier',
            mutate: (view: DataView) => view.setUint32(0, 0, true),
        },
        {
            name: 'format version',
            mutate: (view: DataView) => view.setUint32(4, 2, true),
        },
        {
            name: 'source RNS-limb index',
            mutate: (view: DataView) => view.setUint32(8, 1, true),
        },
        {
            name: 'Shamir coefficient index',
            mutate: (view: DataView) => view.setBigUint64(12, 5n, true),
        },
        {
            name: 'ring degree',
            mutate: (view: DataView) =>
                view.setUint32(20, productionRingDegree / 2, true),
        },
        {
            name: 'commitment-limb count',
            mutate: (view: DataView) => view.setUint32(24, 2, true),
        },
        {
            name: 'row count',
            mutate: (view: DataView) => view.setUint32(28, 1, true),
        },
        {
            name: 'ordered modulus index',
            mutate: (view: DataView) =>
                view.setUint32(
                    structuredCommitmentWorkerResponseHeaderByteLength +
                        limbByteLength,
                    2,
                    true,
                ),
        },
        {
            name: 'out-of-range residue',
            mutate: (view: DataView) =>
                view.setBigUint64(
                    structuredCommitmentWorkerResponseHeaderByteLength +
                        structuredCommitmentWorkerResponseLimbHeaderByteLength,
                    BigInt(dataPrimes[0]),
                    true,
                ),
        },
        {
            name: 'unsafe-integer residue',
            mutate: (view: DataView) =>
                view.setBigUint64(
                    structuredCommitmentWorkerResponseHeaderByteLength +
                        structuredCommitmentWorkerResponseLimbHeaderByteLength,
                    BigInt(Number.MAX_SAFE_INTEGER) + 1n,
                    true,
                ),
        },
    ])('rejects a wrong $name', ({ mutate }) => {
        const frame = encodeResponse();
        mutate(new DataView(frame.buffer));
        expectMalformedResponse(frame);
    });
});
