export type ReceiverKeyLinearProofParameterSet = {
    readonly profileId: 'receiver-key-linear-module-lwe-compatibility-v1';
    readonly source: 'tools/lazer-oracle/receiver-key-linear-params.py';
    readonly relation: 'A*w + t = 0';
    readonly ringDegree: 256;
    readonly proofSystemRingDegree: 64;
    readonly coefficientModulus: 12_289;
    readonly statementRows: 4;
    readonly statementColumns: 8;
    readonly witnessL2BoundSquared: 8_192;
    readonly expectedProofSizeBytes?: number;
};

export type ReceiverKeyLinearProofEncoding = {
    readonly profileId: 'receiver-key-linear-proof-encoding-v1';
    readonly ringDegree: 64;
    readonly coefficientModulus: '274877908477';
    readonly fullSizeCoefficientBitLength: 39;
    readonly compressedCoefficientBitLength: 29;
    readonly targetCommitmentVectorLength: 12;
    readonly hashMaskVectorLength: 2;
    readonly compressedCommitmentVectorLength: 19;
    readonly challengeCoefficientModulus: 17;
    readonly challengeCoefficientBitLength: 5;
    readonly hintVectorLength: 19;
    readonly shortResponseVectorLength: 33;
    readonly randomnessResponseVectorLength: 36;
    readonly euclideanResponseVectorLength: 4;
    readonly infinityResponseVectorLength: 4;
    readonly shortResponseLog2StandardDeviation: 17;
    readonly randomnessResponseLog2StandardDeviation: 12;
    readonly euclideanResponseLog2StandardDeviation: 12;
    readonly infinityResponseLog2StandardDeviation: 17;
    readonly source: 'temp/lazer/python/demo/receiver_key_params.h:receiver_key_param';
    readonly expectedProofSizeBytes?: number;
};

export type ReceiverKeyProofMaterial = {
    readonly proofBytesHex: string;
    readonly proofEncoding: ReceiverKeyLinearProofEncoding;
    readonly proofParameterSet: ReceiverKeyLinearProofParameterSet;
    readonly publicRandomnessHex: string;
};

const proofBytesHexPattern = /^(?:[a-f0-9]{2})+$/u;
const publicRandomnessHexPattern = /^[a-f0-9]{64}$/u;

const validateExpectedProofSizeBytes = (
    expectedProofSizeBytes: number | undefined,
): void => {
    if (
        expectedProofSizeBytes !== undefined &&
        (!Number.isSafeInteger(expectedProofSizeBytes) ||
            expectedProofSizeBytes <= 0)
    ) {
        throw new RangeError(
            'Expected proof size must be a positive safe integer when present.',
        );
    }
};

export const createReceiverKeyLinearProofParameterSet = (input?: {
    readonly expectedProofSizeBytes?: number;
}): ReceiverKeyLinearProofParameterSet => {
    validateExpectedProofSizeBytes(input?.expectedProofSizeBytes);

    return {
        profileId: 'receiver-key-linear-module-lwe-compatibility-v1',
        source: 'tools/lazer-oracle/receiver-key-linear-params.py',
        relation: 'A*w + t = 0',
        ringDegree: 256,
        proofSystemRingDegree: 64,
        coefficientModulus: 12_289,
        statementRows: 4,
        statementColumns: 8,
        witnessL2BoundSquared: 8_192,
        ...(input?.expectedProofSizeBytes === undefined
            ? {}
            : { expectedProofSizeBytes: input.expectedProofSizeBytes }),
    };
};

export const createReceiverKeyLinearProofEncoding = (input?: {
    readonly expectedProofSizeBytes?: number;
}): ReceiverKeyLinearProofEncoding => {
    validateExpectedProofSizeBytes(input?.expectedProofSizeBytes);

    return {
        profileId: 'receiver-key-linear-proof-encoding-v1',
        ringDegree: 64,
        coefficientModulus: '274877908477',
        fullSizeCoefficientBitLength: 39,
        compressedCoefficientBitLength: 29,
        targetCommitmentVectorLength: 12,
        hashMaskVectorLength: 2,
        compressedCommitmentVectorLength: 19,
        challengeCoefficientModulus: 17,
        challengeCoefficientBitLength: 5,
        hintVectorLength: 19,
        shortResponseVectorLength: 33,
        randomnessResponseVectorLength: 36,
        euclideanResponseVectorLength: 4,
        infinityResponseVectorLength: 4,
        shortResponseLog2StandardDeviation: 17,
        randomnessResponseLog2StandardDeviation: 12,
        euclideanResponseLog2StandardDeviation: 12,
        infinityResponseLog2StandardDeviation: 17,
        source: 'temp/lazer/python/demo/receiver_key_params.h:receiver_key_param',
        ...(input?.expectedProofSizeBytes === undefined
            ? {}
            : { expectedProofSizeBytes: input.expectedProofSizeBytes }),
    };
};

export const createReceiverKeyProofMaterial = (input: {
    readonly proofBytesHex: string;
    readonly publicRandomnessHex: string;
}): ReceiverKeyProofMaterial => {
    if (!proofBytesHexPattern.test(input.proofBytesHex)) {
        throw new RangeError(
            'Receiver-key proof bytes must be non-empty lowercase hexadecimal bytes.',
        );
    }
    if (!publicRandomnessHexPattern.test(input.publicRandomnessHex)) {
        throw new RangeError(
            'Receiver-key proof public randomness must be 32 lowercase hexadecimal bytes.',
        );
    }

    const expectedProofSizeBytes = input.proofBytesHex.length / 2;

    return {
        proofBytesHex: input.proofBytesHex,
        proofEncoding: createReceiverKeyLinearProofEncoding({
            expectedProofSizeBytes,
        }),
        proofParameterSet: createReceiverKeyLinearProofParameterSet({
            expectedProofSizeBytes,
        }),
        publicRandomnessHex: input.publicRandomnessHex,
    };
};
