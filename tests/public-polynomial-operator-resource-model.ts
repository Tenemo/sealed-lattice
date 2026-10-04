import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';

// Coefficient-buffer accounting for the consumed PolynomialStream/Operator
// representation. Input polynomials, metadata and allocator allowances are
// supplied by each relation owner; this is not a complete process bound.
export const compilePublicPolynomialOperatorBuffers = (
    degree: bigint,
    coefficientBytes: bigint,
    columns: number,
    residentValueColumns: number,
    buildValueColumns: number,
) => {
    const agreement = compileCommonAgreementDegreeCensus();
    const systematic = BigInt(agreement.systematicSize);
    if (
        degree < 2n ||
        degree > systematic ||
        (degree & (degree - 1n)) !== 0n ||
        coefficientBytes <= 0n ||
        coefficientBytes > 1n << 20n ||
        ![columns, residentValueColumns, buildValueColumns].every(
            Number.isSafeInteger,
        ) ||
        columns <= 0 ||
        residentValueColumns <= 0 ||
        buildValueColumns < residentValueColumns
    )
        throw new RangeError('Invalid public polynomial operator shape.');
    const field = compileSmallLimbProofFieldCensus();
    const extension = field.packedExtensionElementByteLength;
    const base = field.packedFieldElementByteLength;
    const queries = 2n * BigInt(agreement.queries);
    // setup-stream-kernel::CHUNK_LIMIT, rounded down to complete records.
    const chunkRecords = (1n << 20n) / coefficientBytes;
    const operatorEncodingChunkBytes =
        (degree < chunkRecords ? degree : chunkRecords) * coefficientBytes;
    const residentOperatorBytes =
        BigInt(residentValueColumns) * degree * extension;
    // Powers materializes in at_queries. A full-degree Ones term bypasses
    // the transform; a reduced-degree one needs its strided interpolation.
    const queryValueColumns =
        residentValueColumns + 1 + Number(degree < systematic);
    const queryValuesBytes = BigInt(queryValueColumns) * degree * extension;
    const queryOutputBytes =
        BigInt(columns + queryValueColumns) * queries * extension;
    // The scalar kernel transforms one owned input in place, with one
    // extension scratch vector, base twiddles, a selected-index vector
    // (three native usize values; 64-bit allowance also covers Wasm32), and
    // that transform's result before appending it to the aggregate output.
    const queryTemporaryBytes =
        degree * extension +
        (degree - 1n) * base +
        queries * (3n * 8n + extension);
    return {
        residentValueColumns,
        queryValueColumns,
        residentOperatorBytes,
        operatorEncodingChunkBytes,
        operatorBuildBufferBytes:
            BigInt(buildValueColumns) * degree * extension +
            operatorEncodingChunkBytes,
        serializedOperatorColumnBytes: degree * extension,
        queryValuesBytes,
        queryOutputBytes,
        queryTemporaryBytes,
        operatorQueryBufferBytes:
            queryValuesBytes +
            queryOutputBytes +
            queryTemporaryBytes +
            queries * 4n,
    };
};
