import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';

export const compileHashRowCheckpointCensus = (
    rowCount = compileCommonAgreementDegreeCensus().domainSize,
) => {
    const maximumRows = compileCommonAgreementDegreeCensus().domainSize;
    if (
        !Number.isSafeInteger(rowCount) ||
        rowCount < 1 ||
        rowCount > maximumRows
    )
        throw new RangeError('Unsupported checkpoint row count.');
    const rows = BigInt(rowCount);
    // The pinned upstream format is 25 little-endian lanes and one cursor byte.
    const serializedStateBytes = 25n * 8n + 1n;
    const rowsPerChunk = 4096n;
    const tagBytes = 16n;
    const ceiling = (value: bigint, divisor: bigint) =>
        (value + divisor - 1n) / divisor;
    const chunkCount = ceiling(rows, rowsPerChunk);
    const maximumChunkRows = rows < rowsPerChunk ? rows : rowsPerChunk;
    const maximumPlaintextChunkBytes = maximumChunkRows * serializedStateBytes;
    const associatedBytes =
        BigInt(Buffer.byteLength('sha3-512-row-checkpoint/1')) + 64n + 3n * 4n;
    const completeChunks = rows / rowsPerChunk;
    const remainingRows = rows % rowsPerChunk;
    const plaintextBlockInputs =
        completeChunks * ((rowsPerChunk * serializedStateBytes) / 16n) +
        ceiling(remainingRows * serializedStateBytes, 16n);
    return {
        rowCount,
        maximumRows,
        serializedStateBytes,
        rowsPerChunk,
        chunkCount,
        maximumPlaintextChunkBytes,
        maximumSealedChunkBytes: maximumPlaintextChunkBytes + tagBytes,
        plaintextBytes: rows * serializedStateBytes,
        sealedBytes: rows * serializedStateBytes + chunkCount * tagBytes,
        associatedBytes,
        distinctAesBlockInputs: 1n + chunkCount + plaintextBlockInputs,
        maximumAuthenticationPolynomialDegree:
            ceiling(associatedBytes, 16n) +
            ceiling(maximumPlaintextChunkBytes, 16n) +
            1n,
    };
};
