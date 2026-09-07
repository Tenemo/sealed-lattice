import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { compileSetupContributionRelationCensus } from '#tests/setup-contribution-relation-model.js';

export const compileFirstOracleCheckpointCensus = () => {
    const proof = compileCommonAgreementDegreeCensus();
    const relation = compileSetupContributionRelationCensus();
    const body = compileContributionBodyCensus();
    const systematic = BigInt(proof.systematicSize);
    const domain = BigInt(proof.domainSize);
    const columns = BigInt(relation.wordColumns + relation.booleanColumns);
    const fields = [
        { name: 'witness columns', units: columns * systematic, unitBytes: 2n },
        {
            name: 'base masks',
            units: (columns + 1n) * BigInt(proof.maskDimension),
            unitBytes: 16n,
        },
        { name: 'degree mask', units: 2n * systematic, unitBytes: 48n },
        { name: 'leaf salts', units: domain, unitBytes: 128n },
        { name: 'partial row hashes', units: domain, unitBytes: 25n * 8n + 1n },
    ].map((field) => {
        const unitsPerRecord = 16384n / field.unitBytes;
        const recordCount =
            (field.units + unitsPerRecord - 1n) / unitsPerRecord;
        return {
            ...field,
            unitsPerRecord,
            recordCount,
            plaintextBytes: field.units * field.unitBytes,
        };
    });
    const recordCount = fields.reduce(
        (count, field) => count + field.recordCount,
        0n,
    );
    const plaintextBytes = fields.reduce(
        (count, field) => count + field.plaintextBytes,
        0n,
    );
    const publicPlaintextBytes =
        relation.expandedStatementHeaderByteLength +
        body.polynomialPayloadBytes;
    const publicRecordCount =
        1n +
        body.polynomials.reduce(
            (count, polynomial) =>
                count + (polynomial.bytes + (1n << 20n) - 1n) / (1n << 20n),
            0n,
        );
    const maximumHeaderBytes =
        4n +
        4n +
        2n +
        1024n +
        64n +
        64n +
        relation.expandedStatementHeaderByteLength;
    const maximumRootPlaintextBytes =
        80n + maximumHeaderBytes + 106n * publicRecordCount + 96n * recordCount;
    return {
        fields,
        recordCount,
        plaintextBytes,
        ciphertextBytes: plaintextBytes + 16n * recordCount,
        dataKeyBytes: 32n * recordCount,
        recordHashBytes: 64n * recordCount,
        maximumPlaintextRecordBytes: 16384n,
        maximumCiphertextRecordBytes: 16384n + 16n,
        maximumHeaderBytes,
        publicRecordCount,
        publicPlaintextBytes,
        publicCiphertextBytes: publicPlaintextBytes + 16n * publicRecordCount,
        maximumRootPlaintextBytes,
        maximumRetainedPayloadBytes:
            plaintextBytes +
            16n * recordCount +
            publicPlaintextBytes +
            16n * publicRecordCount +
            maximumRootPlaintextBytes +
            16n,
    };
};
