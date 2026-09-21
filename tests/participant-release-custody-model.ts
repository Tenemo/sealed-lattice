import { compileFixedModulusBfvCensus } from '#tests/fixed-modulus-bfv-model.js';
import { compileLinkedReleaseWordProofLayout } from '#tests/full-word-proof-layout-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import { compileTargetSigningStateCensus } from '#tests/target-signing-state-model.js';

// A finite journal of independent bytes for one original-key release. The
// proof budget bounds rejection-sampling exhaustion; it is not a PRG claim.
export const compileParticipantReleaseCustody = () => {
    const parameters = compileFixedModulusBfvCensus();
    const proof = compileLinkedReleaseWordProofLayout();
    const field = compileSmallLimbProofFieldCensus();
    const { signatureBytes } = compileRegistrationEnrollmentCensus();
    const readBytes = 65_536n;
    const recordBytes = 1n << 20n;
    const exhaustionAllocationBits = 128n;
    const rejected = (1n << field.modulusBitLength) - field.modulus;
    const failure = (extraReads: bigint) => {
        const rejections = extraReads + 1n;
        const candidates =
            (proof.minimumRequestedRandomBytes + extraReads * readBytes) /
            field.packedFieldElementByteLength;
        let subsets = 1n;
        for (let index = 1n; index <= rejections; index++)
            subsets = (subsets * (candidates - index + 1n)) / index;
        return {
            numerator:
                parameters.participantCount * subsets * rejected ** rejections,
            denominatorBits: field.modulusBitLength * rejections,
        };
    };
    let extraProofReads = 0n;
    while (
        failure(extraProofReads).numerator << exhaustionAllocationBits >
        1n << failure(extraProofReads).denominatorBits
    )
        extraProofReads++;
    const exhaustionBound = failure(extraProofReads);
    if (parameters.releaseNoiseBits % 8 !== 0)
        throw new Error('Release noise requires an exact byte width.');
    const noiseBytes =
        parameters.polynomialDegree * BigInt(parameters.releaseNoiseBits / 8);
    const roundedNoiseBytes =
        ((noiseBytes + readBytes - 1n) / readBytes) * readBytes;
    const maximumProofRandomBytes =
        proof.minimumRequestedRandomBytes + extraProofReads * readBytes;
    const totalRandomBytes = roundedNoiseBytes + maximumProofRandomBytes;
    const journalRecords = (totalRandomBytes + recordBytes - 1n) / recordBytes;
    const contextBytes = 4n + 3n * 64n + 2n;
    const bodyHeaderBytes = 4n + 8n + contextBytes;
    const coefficientBytes =
        1n + (BigInt(parameters.releaseModulus.toString(2).length) + 7n) / 8n;
    const partialBytes = parameters.polynomialDegree * coefficientBytes;
    const minimumBodyBytes = bodyHeaderBytes + partialBytes + proof.headerBytes;
    const maximumBodyBytes =
        bodyHeaderBytes + partialBytes + proof.maximumMultiproofBytes;
    const envelopeBytes = contextBytes + 8n + 64n;
    const maximumBodyRecords =
        (maximumBodyBytes + recordBytes - 1n) / recordBytes;
    const prefixBytes = 4n + 1n + 2n + 2n + 4n + 2n;
    const targetBytes = compileTargetSigningStateCensus().maximumBodyBytes;
    const phaseBytes = [
        {
            phase: 26,
            bytes: prefixBytes + targetBytes + 32n * (journalRecords - 1n),
        },
        { phase: 27, bytes: prefixBytes + targetBytes + 32n * journalRecords },
        {
            phase: 28,
            bytes:
                prefixBytes +
                targetBytes +
                32n * (journalRecords + maximumBodyRecords) +
                envelopeBytes,
        },
        {
            phase: 29,
            bytes:
                prefixBytes +
                targetBytes +
                32n * (journalRecords + maximumBodyRecords) +
                envelopeBytes +
                32n,
        },
        {
            phase: 30,
            bytes:
                prefixBytes +
                targetBytes +
                32n * maximumBodyRecords +
                envelopeBytes +
                signatureBytes,
        },
    ];
    return {
        readBytes,
        recordBytes,
        exhaustionAllocationBits,
        exhaustionBound,
        extraProofReads,
        noiseBytes,
        roundedNoiseBytes,
        maximumProofRandomBytes,
        totalRandomBytes,
        journalRecords,
        wasmEntropyInputBytes: recordBytes,
        wasmEntropyOutputBytes: readBytes,
        maximumWasmEntropyPayloadBytes:
            totalRandomBytes + recordBytes + readBytes,
        maximumLiveDecryptedJournalRecordBytes: recordBytes,
        bodyHeaderBytes,
        partialBytes,
        minimumBodyBytes,
        maximumBodyBytes,
        envelopeBytes,
        signatureBytes,
        maximumBodyRecords,
        prefixBytes,
        phaseBytes,
        maximumStateBytes: phaseBytes.reduce(
            (maximum, value) => (value.bytes > maximum ? value.bytes : maximum),
            0n,
        ),
        encryptedJournalBytes: totalRandomBytes + 16n * journalRecords,
        maximumEncryptedBodyBytes: maximumBodyBytes + 16n * maximumBodyRecords,
        maximumJournalAndBodyBytes:
            totalRandomBytes +
            maximumBodyBytes +
            16n * (journalRecords + maximumBodyRecords),
    };
};
