import { BrowserActionStorageCustodyError } from '@sealed-lattice/types';

export type BgvSetupCommitmentOpeningComputation = Readonly<{
    commitment: Readonly<{
        objectType: 'SetupCommitment';
        sourceRnsLimbIndex: number;
        shamirCoefficientIndex: number;
        ringDegree: number;
        commitmentLimbs: readonly Readonly<{
            rows: readonly (readonly number[])[];
        }>[];
    }>;
}>;

export const structuredCommitmentWorkerResponseFormatIdentifier = 0x4d43_4c53;
export const structuredCommitmentWorkerResponseVersion = 1;
export const structuredCommitmentWorkerResponseHeaderByteLength = 32;
export const structuredCommitmentWorkerResponseLimbHeaderByteLength = 4;
export const structuredCommitmentModulusIndices = Object.freeze([0, 1, 2]);
export const structuredCommitmentRowCount = 2;
const productionStructuredCommitmentRingDegree = 32_768;
const unsigned64ByteLength = 8;

const structuredCommitmentWorkerResponseByteLength = (
    ringDegree: number,
): number =>
    structuredCommitmentWorkerResponseHeaderByteLength +
    structuredCommitmentModulusIndices.length *
        structuredCommitmentWorkerResponseLimbHeaderByteLength +
    structuredCommitmentModulusIndices.length *
        structuredCommitmentRowCount *
        ringDegree *
        unsigned64ByteLength;

export const structuredCommitmentWorkerResponseProductionByteLength =
    structuredCommitmentWorkerResponseByteLength(
        productionStructuredCommitmentRingDegree,
    );

const maximumSafeIntegerBigInt = BigInt(Number.MAX_SAFE_INTEGER);

export const decodeStructuredCommitmentWorkerResponse = (input: {
    bytes: Uint8Array;
    dataPrimes: readonly number[];
    expectedRingDegree: number;
    expectedShamirCoefficientIndex: number;
    expectedSourceRnsLimbIndex: number;
}): BgvSetupCommitmentOpeningComputation => {
    const {
        bytes,
        dataPrimes,
        expectedRingDegree,
        expectedShamirCoefficientIndex,
        expectedSourceRnsLimbIndex,
    } = input;
    if (!(bytes instanceof Uint8Array)) {
        throwMalformedResponse('The response is not a byte array.');
    }
    requireNonnegativeSafeInteger(expectedRingDegree, 'Expected ring degree');
    requireNonnegativeSafeInteger(
        expectedShamirCoefficientIndex,
        'Expected Shamir coefficient index',
    );
    requireNonnegativeSafeInteger(
        expectedSourceRnsLimbIndex,
        'Expected source RNS-limb index',
    );
    if (
        expectedRingDegree === 0 ||
        !Array.isArray(dataPrimes) ||
        expectedSourceRnsLimbIndex >= dataPrimes.length
    ) {
        throwMalformedResponse(
            'The expected setup-commitment parameter shape is invalid.',
        );
    }
    const selectedModuli = structuredCommitmentModulusIndices.map(
        (modulusIndex) => {
            const modulus = dataPrimes[modulusIndex];
            if (
                typeof modulus !== 'number' ||
                !Number.isSafeInteger(modulus) ||
                modulus <= 0
            ) {
                throwMalformedResponse(
                    'A selected setup-commitment modulus is invalid.',
                );
            }
            return modulus;
        },
    );
    const expectedByteLength =
        structuredCommitmentWorkerResponseByteLength(expectedRingDegree);
    if (
        !Number.isSafeInteger(expectedByteLength) ||
        bytes.byteLength !== expectedByteLength
    ) {
        throwMalformedResponse(
            'The response length does not match the fixed setup-commitment shape.',
        );
    }

    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (
        view.getUint32(0, true) !==
            structuredCommitmentWorkerResponseFormatIdentifier ||
        view.getUint32(4, true) !== structuredCommitmentWorkerResponseVersion
    ) {
        throwMalformedResponse(
            'The response format identifier or version is unsupported.',
        );
    }
    const sourceRnsLimbIndex = view.getUint32(8, true);
    const shamirCoefficientIndex = readSafeUnsigned64(
        view,
        12,
        'Shamir coefficient index',
    );
    const ringDegree = view.getUint32(20, true);
    const commitmentLimbCount = view.getUint32(24, true);
    const rowCount = view.getUint32(28, true);
    if (
        sourceRnsLimbIndex !== expectedSourceRnsLimbIndex ||
        shamirCoefficientIndex !== expectedShamirCoefficientIndex ||
        ringDegree !== expectedRingDegree
    ) {
        throwMalformedResponse(
            'The response coordinates do not match the retained opening.',
        );
    }
    if (
        commitmentLimbCount !== structuredCommitmentModulusIndices.length ||
        rowCount !== structuredCommitmentRowCount
    ) {
        throwMalformedResponse(
            'The response limb or row count is outside the selected shape.',
        );
    }

    let byteOffset = structuredCommitmentWorkerResponseHeaderByteLength;
    const commitmentLimbs: Array<{
        rows: number[][];
    }> = [];
    for (
        let commitmentLimbPosition = 0;
        commitmentLimbPosition < structuredCommitmentModulusIndices.length;
        commitmentLimbPosition += 1
    ) {
        const expectedModulusIndex =
            structuredCommitmentModulusIndices[commitmentLimbPosition];
        const modulus = selectedModuli[commitmentLimbPosition];
        if (expectedModulusIndex === undefined || modulus === undefined) {
            throwMalformedResponse(
                'The selected setup-commitment modulus shape is incomplete.',
            );
        }
        if (view.getUint32(byteOffset, true) !== expectedModulusIndex) {
            throwMalformedResponse(
                'The response modulus indices are not in selected order.',
            );
        }
        byteOffset += structuredCommitmentWorkerResponseLimbHeaderByteLength;
        const rows: number[][] = [];
        for (let rowIndex = 0; rowIndex < rowCount; rowIndex += 1) {
            const row = new Array<number>(ringDegree);
            for (
                let coefficientIndex = 0;
                coefficientIndex < ringDegree;
                coefficientIndex += 1
            ) {
                const residue = readSafeUnsigned64(
                    view,
                    byteOffset,
                    `Commitment residue ${String(commitmentLimbPosition)}:${String(rowIndex)}:${String(coefficientIndex)}`,
                );
                if (residue >= modulus) {
                    throwMalformedResponse(
                        'A response residue is outside its selected commitment modulus.',
                    );
                }
                row[coefficientIndex] = residue;
                byteOffset += unsigned64ByteLength;
            }
            rows.push(row);
        }
        commitmentLimbs.push({ rows });
    }
    if (byteOffset !== bytes.byteLength) {
        throwMalformedResponse(
            'The response contains trailing structured-commitment bytes.',
        );
    }

    return {
        commitment: {
            objectType: 'SetupCommitment',
            sourceRnsLimbIndex,
            shamirCoefficientIndex,
            ringDegree,
            commitmentLimbs,
        },
    };
};

const readSafeUnsigned64 = (
    view: DataView,
    byteOffset: number,
    label: string,
): number => {
    const value = view.getBigUint64(byteOffset, true);
    if (value > maximumSafeIntegerBigInt) {
        throwMalformedResponse(`${label} is not a safe JavaScript integer.`);
    }
    return Number(value);
};

const requireNonnegativeSafeInteger = (value: number, label: string): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throwMalformedResponse(`${label} is invalid.`);
    }
};

const throwMalformedResponse = (detail: string): never => {
    throw new BrowserActionStorageCustodyError(
        'OwnedWorkerFailure',
        `The WASM action-randomness kernel returned a malformed structured commitment. ${detail}`,
    );
};
