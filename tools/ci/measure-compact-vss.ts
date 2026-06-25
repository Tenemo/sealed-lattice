import { performance } from 'node:perf_hooks';

import { deriveProtocolHash } from '#packages/crypto/src/index.js';
import {
    compactVssCommitmentMeasurement,
    computeCompactVssCommitmentFromOpening,
    decodeCompactVssCommitmentBody,
    encodeCompactVssCommitmentBody,
    verifyCompactVssCommitmentOpening,
    type CompactVssCommitmentBodyMetadata,
    type CompactVssCommitmentOpeningInput,
    type CompactVssCommitmentValue,
} from '#packages/protocol/src/setup/compact-vss-commitments.js';
import {
    acceptedBgvProfileRingDegree,
    acceptedBgvSetupQSharePrimes,
} from '#packages/protocol/src/setup/vss-coefficient-commitments.js';
import { loadTranscriptCoreKernel } from '#packages/wasm/src/index.js';
import type {
    BgvCompactVssCommitmentBodyMetadata,
    BgvCompactVssCommitmentOpeningInput,
    TranscriptCoreKernel,
} from '#packages/wasm/src/transcript-core-bridge.js';

const warmRunCount = 5;
const firstProfileParticipantCount = 10;
const firstProfileThresholdDegree = 4;
const currentFullCoefficientTransportBytes = 1_604_341_697;
const targetRnsLimbCount = 7;

type TimedSamples = Readonly<{
    readonly coldMilliseconds: number;
    readonly warmMedianMilliseconds: number;
    readonly warmSamplesMilliseconds: readonly number[];
}>;

type MeasuredOperation<Result> = Readonly<{
    readonly samples: TimedSamples;
    readonly lastResult: Result;
}>;

type TypeScriptPathMeasurement = Readonly<{
    readonly generation: MeasuredOperation<
        ReturnType<typeof computeCompactVssCommitmentFromOpening>
    >;
    readonly bodyEncoding: MeasuredOperation<Uint8Array>;
    readonly bodyDecoding: MeasuredOperation<CompactVssCommitmentValue>;
    readonly verification: MeasuredOperation<
        ReturnType<typeof verifyCompactVssCommitmentOpening>
    >;
}>;

type WasmPathMeasurement = Readonly<{
    readonly generation: MeasuredOperation<
        ReturnType<
            TranscriptCoreKernel['computeCompactVssCommitmentFromOpening']
        >
    >;
    readonly bodyEncoding: MeasuredOperation<
        ReturnType<TranscriptCoreKernel['encodeCompactVssCommitmentBody']>
    >;
    readonly bodyDecoding: MeasuredOperation<
        ReturnType<TranscriptCoreKernel['decodeCompactVssCommitmentBody']>
    >;
    readonly verification: MeasuredOperation<
        ReturnType<TranscriptCoreKernel['verifyCompactVssCommitmentOpening']>
    >;
}>;

const median = (samples: readonly number[]): number => {
    const sortedSamples = [...samples].sort((left, right) => left - right);
    const middleIndex = Math.floor(sortedSamples.length / 2);
    const middleValue = sortedSamples[middleIndex];
    if (middleValue === undefined) {
        throw new Error('measurement requires at least one sample.');
    }

    return middleValue;
};

const timed = <Result>(
    operation: () => Result,
): Readonly<{
    readonly result: Result;
    readonly milliseconds: number;
}> => {
    const startedAtMilliseconds = performance.now();
    const result = operation();
    const milliseconds = performance.now() - startedAtMilliseconds;

    return { result, milliseconds };
};

const fullRingOpening = (): CompactVssCommitmentOpeningInput => {
    const publicMatrixSeedHash = deriveProtocolHash(
        'SetupPublicMatrixSeedHash',
        {
            measurement: 'compact-vss',
            label: 'manual-cpu-sanity',
        },
    );
    const rnsPrime = acceptedBgvSetupQSharePrimes[0];
    if (rnsPrime === undefined) {
        throw new Error('accepted profile must define at least one RNS prime.');
    }
    const messageCoefficients = Array.from(
        { length: acceptedBgvProfileRingDegree },
        (_unused, coefficientIndex) =>
            (coefficientIndex * 65_537 + 17) % rnsPrime,
    );
    const randomnessByColumn = [0, 1].map((columnIndex) =>
        Array.from(
            { length: acceptedBgvProfileRingDegree },
            (_unused, coefficientIndex) => {
                const residue = (coefficientIndex + columnIndex * 2) % 5;

                return residue - 2;
            },
        ),
    );

    return {
        commitmentRole: 'aggregate-threshold-share',
        commitmentContext: {
            objectType: 'CompactVssAggregateThresholdShareCommitmentContext',
            objectVersion: 1,
            ceremonyId: 'compact-vss-measurement',
            recipientIdentity: 'trustee-1',
            recipientRosterPosition: 0,
            rnsLimbIndex: 0,
            rnsPrime,
        },
        publicMatrixSeedHash,
        rnsLimbIndex: 0,
        rnsPrime,
        ringDegree: acceptedBgvProfileRingDegree,
        messageCoefficients,
        randomnessByColumn,
    };
};

const measureSyncOperation = <Result>(
    operation: () => Result,
): MeasuredOperation<Result> => {
    const cold = timed(operation);
    const warmMeasurements: number[] = [];
    let lastResult = cold.result;
    for (let runIndex = 0; runIndex < warmRunCount; runIndex += 1) {
        const warm = timed(operation);
        warmMeasurements.push(warm.milliseconds);
        lastResult = warm.result;
    }

    return {
        samples: {
            coldMilliseconds: cold.milliseconds,
            warmMedianMilliseconds: median(warmMeasurements),
            warmSamplesMilliseconds: warmMeasurements,
        },
        lastResult,
    };
};

const compactCommitmentBodyMetadata = (
    commitment: CompactVssCommitmentValue,
): CompactVssCommitmentBodyMetadata => ({
    commitmentRole: commitment.commitmentRole,
    commitmentContextHash: commitment.commitmentContextHash,
    publicMatrixSeedHash: commitment.publicMatrixSeedHash,
    rnsLimbIndex: commitment.rnsLimbIndex,
    rnsPrime: commitment.rnsPrime,
    ringDegree: commitment.ringDegree,
    messageVectorHash512: commitment.messageVectorHash512,
    openingRandomnessHash512: commitment.openingRandomnessHash512,
});

const measureTypeScriptPath = (
    opening: CompactVssCommitmentOpeningInput,
): TypeScriptPathMeasurement => {
    const generation = measureSyncOperation(() =>
        computeCompactVssCommitmentFromOpening(opening),
    );
    const metadata = compactCommitmentBodyMetadata(
        generation.lastResult.commitment,
    );
    const bodyEncoding = measureSyncOperation(() =>
        encodeCompactVssCommitmentBody(generation.lastResult.commitment),
    );
    const bodyDecoding = measureSyncOperation(() =>
        decodeCompactVssCommitmentBody({
            metadata,
            commitmentBodyBytes: bodyEncoding.lastResult,
        }),
    );
    const verification = measureSyncOperation(() =>
        verifyCompactVssCommitmentOpening({
            opening,
            expectedCommitmentRoot: generation.lastResult.commitmentRoot,
        }),
    );

    return { generation, bodyEncoding, bodyDecoding, verification };
};

const measureWasmPath = (
    kernel: TranscriptCoreKernel,
    opening: BgvCompactVssCommitmentOpeningInput,
    metadata: BgvCompactVssCommitmentBodyMetadata,
): WasmPathMeasurement => {
    const generation = measureSyncOperation(() =>
        kernel.computeCompactVssCommitmentFromOpening(opening),
    );
    const bodyEncoding = measureSyncOperation(() =>
        kernel.encodeCompactVssCommitmentBody({
            commitment: generation.lastResult.commitment,
        }),
    );
    const bodyDecoding = measureSyncOperation(() =>
        kernel.decodeCompactVssCommitmentBody({
            metadata,
            commitmentBodyBytes: bodyEncoding.lastResult.commitmentBodyBytes,
        }),
    );
    const verification = measureSyncOperation(() =>
        kernel.verifyCompactVssCommitmentOpening({
            opening,
            expectedCommitmentRoot: generation.lastResult.commitmentRoot,
        }),
    );

    return { generation, bodyEncoding, bodyDecoding, verification };
};

const scaledSeconds = (
    millisecondsPerCommitment: number,
    totalCommitments: number,
): number => (millisecondsPerCommitment * totalCommitments) / 1_000;

const equalBytes = (left: Uint8Array, right: Uint8Array): boolean =>
    left.byteLength === right.byteLength &&
    left.every((leftByte, byteIndex) => leftByte === right[byteIndex]);

const main = async (): Promise<void> => {
    const opening = fullRingOpening();
    const measurement = compactVssCommitmentMeasurement({
        participantCount: firstProfileParticipantCount,
        sourceRnsLimbCount: acceptedBgvSetupQSharePrimes.length,
        targetRnsLimbCount,
        thresholdDegree: firstProfileThresholdDegree,
        currentFullCoefficientTransportBytes,
    });
    const typeScriptMeasurement = measureTypeScriptPath(opening);
    const kernel = await loadTranscriptCoreKernel();
    const metadata = compactCommitmentBodyMetadata(
        typeScriptMeasurement.generation.lastResult.commitment,
    );
    const wasmMeasurement = measureWasmPath(kernel, opening, metadata);
    if (
        typeScriptMeasurement.generation.lastResult.commitmentRoot !==
        wasmMeasurement.generation.lastResult.commitmentRoot
    ) {
        throw new Error(
            'TypeScript and WASM compact VSS commitment roots differ.',
        );
    }
    if (
        typeScriptMeasurement.bodyEncoding.lastResult.byteLength !==
            measurement.singleCompactCommitmentBytes ||
        wasmMeasurement.bodyEncoding.lastResult.commitmentBodyBytes
            .byteLength !== measurement.singleCompactCommitmentBytes
    ) {
        throw new Error(
            'compact VSS encoded commitment body length differs from the static byte accounting.',
        );
    }
    if (
        !equalBytes(
            typeScriptMeasurement.bodyEncoding.lastResult,
            wasmMeasurement.bodyEncoding.lastResult.commitmentBodyBytes,
        )
    ) {
        throw new Error(
            'TypeScript and WASM compact VSS encoded commitment bodies differ.',
        );
    }
    if (
        wasmMeasurement.bodyDecoding.lastResult.commitmentRoot !==
        typeScriptMeasurement.generation.lastResult.commitmentRoot
    ) {
        throw new Error(
            'WASM compact VSS decoded commitment root differs from the generated commitment root.',
        );
    }

    const totalCommitments =
        measurement.cpuWorkModel.sourceCoefficientCommitments +
        measurement.cpuWorkModel.recipientShareCommitments +
        measurement.cpuWorkModel.aggregateThresholdCommitments;

    console.log(
        JSON.stringify(
            {
                objectType: 'CompactVssManualMeasurementReport',
                objectVersion: 1,
                measurementScope:
                    'manual local CPU sanity and static compact VSS public commitment accounting; not supported-phone evidence',
                ringDegree: opening.ringDegree,
                warmRunCount,
                totalCommitments,
                byteReduction: measurement.byteReduction,
                totalCompactPublicCommitmentBytes:
                    measurement.totalCompactPublicCommitmentBytes,
                currentFullCoefficientTransportBytes:
                    measurement.currentFullCoefficientTransportBytes,
                cpuWorkModel: measurement.cpuWorkModel,
                typeScript: {
                    generation: typeScriptMeasurement.generation.samples,
                    bodyEncoding: typeScriptMeasurement.bodyEncoding.samples,
                    bodyDecoding: typeScriptMeasurement.bodyDecoding.samples,
                    verification: typeScriptMeasurement.verification.samples,
                    warmGenerationExtrapolatedSeconds: scaledSeconds(
                        typeScriptMeasurement.generation.samples
                            .warmMedianMilliseconds,
                        totalCommitments,
                    ),
                    warmVerificationExtrapolatedSeconds: scaledSeconds(
                        typeScriptMeasurement.verification.samples
                            .warmMedianMilliseconds,
                        totalCommitments,
                    ),
                },
                wasm: {
                    generation: wasmMeasurement.generation.samples,
                    bodyEncoding: wasmMeasurement.bodyEncoding.samples,
                    bodyDecoding: wasmMeasurement.bodyDecoding.samples,
                    verification: wasmMeasurement.verification.samples,
                    warmGenerationExtrapolatedSeconds: scaledSeconds(
                        wasmMeasurement.generation.samples
                            .warmMedianMilliseconds,
                        totalCommitments,
                    ),
                    warmVerificationExtrapolatedSeconds: scaledSeconds(
                        wasmMeasurement.verification.samples
                            .warmMedianMilliseconds,
                        totalCommitments,
                    ),
                },
            },
            null,
            2,
        ),
    );
};

await main();
