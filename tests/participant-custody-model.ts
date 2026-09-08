import { compileContributionAuthenticationCensus } from '#tests/contribution-authentication-model.js';
import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { compileFirstOracleCheckpointCensus } from '#tests/first-oracle-checkpoint-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import { compileSetupContributionRelationCensus } from '#tests/setup-contribution-relation-model.js';

export const compileParticipantCustodyCensus = () => {
    const body = compileContributionBodyCensus();
    const checkpoint = compileFirstOracleCheckpointCensus();
    const enrollment = compileRegistrationEnrollmentCensus();
    const authentication = compileContributionAuthenticationCensus(
        body.participantCount,
    );
    const relation = compileSetupContributionRelationCensus();
    const chunkBytes = 1n << 20n;
    const publicRecords = body.polynomials.flatMap((polynomial) => {
        const records = [];
        for (let offset = 0n; offset < polynomial.bytes; offset += chunkBytes) {
            const remaining = polynomial.bytes - offset;
            records.push({
                object: polynomial.expandedIndex + 1,
                offset,
                length: remaining < chunkBytes ? remaining : chunkBytes,
            });
        }
        return records;
    });
    const checkpointLengths = checkpoint.fields.flatMap((field) => {
        const lengths = [];
        for (let used = 0n; used < field.units; used += field.unitsPerRecord) {
            const remaining = field.units - used;
            lengths.push(
                (remaining < field.unitsPerRecord
                    ? remaining
                    : field.unitsPerRecord) *
                    field.unitBytes +
                    16n,
            );
        }
        return lengths;
    });
    const maximumProofRecords =
        (body.maximumProofBytes + chunkBytes - 1n) / chunkBytes;
    const metadataPrefixBytes = 4n + 2n + body.saltBytes + 4n * 4n;
    const maximumCheckpointMetadataBytes =
        metadataPrefixBytes +
        checkpoint.maximumHeaderBytes +
        106n * BigInt(publicRecords.length) +
        96n * checkpoint.recordCount;
    const maximumCompletedMetadataBytes =
        metadataPrefixBytes +
        106n * (BigInt(publicRecords.length) + maximumProofRecords) +
        5n * 102n;
    const maximumMetadataBytes =
        maximumCheckpointMetadataBytes > maximumCompletedMetadataBytes
            ? maximumCheckpointMetadataBytes
            : maximumCompletedMetadataBytes;
    const maximumRootRecords = enrollment.maximumRecords + 1n;
    const setupReferenceBytes =
        4n + 64n + 64n * BigInt(body.polynomials.length);
    const maximumRootBytes =
        enrollment.manifestPrefixBytes +
        73n * maximumRootRecords +
        4n +
        maximumMetadataBytes +
        16n;
    const maximumPublicBodyCiphertextBytes =
        body.polynomialPayloadBytes +
        body.maximumProofBytes +
        16n * (BigInt(publicRecords.length) + maximumProofRecords);
    const maximumSigningPlaintextBytes =
        authentication.confirmationBodyBytes +
        authentication.openingBodyBytes +
        2n * authentication.signatureBytes +
        4n +
        BigInt(body.participantCount) * authentication.confirmationPacketBytes;
    const maximumRetainedPayloadBytes =
        enrollment.maximumRetainedPayloadBytes -
        enrollment.maximumRootBytes +
        maximumRootBytes +
        setupReferenceBytes +
        maximumPublicBodyCiphertextBytes +
        checkpoint.ciphertextBytes +
        maximumSigningPlaintextBytes +
        5n * 16n;
    return {
        participants: body.participantCount,
        publicRecords,
        checkpointLengths,
        metadataPrefixBytes,
        maximumCheckpointMetadataBytes,
        maximumCompletedMetadataBytes,
        maximumMetadataBytes,
        maximumRootRecords,
        setupReferenceBytes,
        maximumRootBytes,
        maximumPublicBodyCiphertextBytes,
        maximumSigningPlaintextBytes,
        maximumRetainedPayloadBytes,
        expandedStatementBytes: relation.expandedStatementByteLength,
    };
};
