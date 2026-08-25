import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';

import { buildOptimizedWasmKernelArtifact } from './build-wasm-kernel.js';
import { resolvePreparationFieldWasmMeasurement } from './preparation-field-wasm-measurement-registry.js';

import { foundationProfile } from '#packages/types/src/foundation-contract.js';

const repoRoot = path.resolve(
    fileURLToPath(new URL('../../', import.meta.url)),
);
const measurementTemporaryRoot = path.resolve(
    repoRoot,
    'temp',
    'build-scratch',
    'preparation-field-wasm-measurements',
);
const measurementCargoTargetDirectory = path.resolve(
    repoRoot,
    'target',
    'wasm-preparation-field-measurement',
);
const diagnosticExportName =
    'sealed_lattice_measure_binary_field_320_multiplications';
const unsignedWordBitLength = 64;

type ParsedWorkerArguments = Readonly<{
    measurementId: string;
    outputFilePath: string;
}>;

type MeasurementFunction = (
    multiplicationCount: number,
    seed: bigint,
) => bigint;

export const parsePreparationFieldWasmMeasurementWorkerArguments = (
    commandArguments: readonly string[],
): ParsedWorkerArguments => {
    let measurementId: string | undefined;
    let outputFilePath: string | undefined;

    for (
        let argumentPosition = 0;
        argumentPosition < commandArguments.length;
    ) {
        const argument = commandArguments[argumentPosition];
        const value = commandArguments[argumentPosition + 1];
        if (argument === '--measurement' && value !== undefined) {
            measurementId = value;
            argumentPosition += 2;
            continue;
        }
        if (argument === '--output' && value !== undefined) {
            outputFilePath = value;
            argumentPosition += 2;
            continue;
        }
        throw new Error(
            `Unknown or incomplete preparation-field measurement worker argument: ${argument ?? '<missing>'}.`,
        );
    }

    if (measurementId === undefined || measurementId.length === 0) {
        throw new Error('The measurement worker requires --measurement.');
    }
    if (outputFilePath === undefined || outputFilePath.length === 0) {
        throw new Error('The measurement worker requires --output.');
    }
    if (!path.isAbsolute(outputFilePath)) {
        throw new Error('The measurement worker output path must be absolute.');
    }

    return { measurementId, outputFilePath };
};

const resolveMeasurementFunction = (
    exports: WebAssembly.Exports,
): MeasurementFunction => {
    const candidate = exports[diagnosticExportName];
    if (typeof candidate !== 'function') {
        throw new Error(
            `The diagnostic WebAssembly build does not export ${diagnosticExportName}.`,
        );
    }
    return candidate as unknown as MeasurementFunction;
};

const resolveMemory = (exports: WebAssembly.Exports): WebAssembly.Memory => {
    const memory = exports.memory;
    if (!(memory instanceof WebAssembly.Memory)) {
        throw new Error(
            'The diagnostic WebAssembly build does not export linear memory.',
        );
    }
    return memory;
};

const unsignedWordHex = (value: bigint): string =>
    BigInt.asUintN(unsignedWordBitLength, value)
        .toString(16)
        .padStart(unsignedWordBitLength / 4, '0');

export const runPreparationFieldWasmMeasurementWorker = async (
    rawArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    const parsedArguments =
        parsePreparationFieldWasmMeasurementWorkerArguments(rawArguments);
    const measurement = resolvePreparationFieldWasmMeasurement(
        parsedArguments.measurementId,
    );
    if (
        !Number.isSafeInteger(measurement.multiplicationCount) ||
        measurement.multiplicationCount < 1 ||
        measurement.multiplicationCount > 0xffff_ffff ||
        !Number.isSafeInteger(measurement.warmupMultiplicationCount) ||
        measurement.warmupMultiplicationCount < 1 ||
        measurement.warmupMultiplicationCount > 0xffff_ffff
    ) {
        throw new Error(
            'Preparation-field measurement counts must be positive u32 values.',
        );
    }

    await mkdir(measurementTemporaryRoot, { recursive: true });
    const temporaryDirectoryPath = await mkdtemp(
        path.join(measurementTemporaryRoot, 'run-'),
    );
    try {
        const wasmOutputFilePath = path.join(
            temporaryDirectoryPath,
            'kernel.wasm',
        );
        const builtArtifact = await buildOptimizedWasmKernelArtifact({
            artifactLabel: 'Preparation-field measurement kernel',
            cargoFeatures: ['preparation-field-measurement'],
            outputFilePath: wasmOutputFilePath,
            scratchDirectoryPrefix: 'preparation-field-measurement-',
            targetDirectoryPath: measurementCargoTargetDirectory,
        });
        const wasmBytes = await readFile(wasmOutputFilePath);
        const instantiatedSource = await WebAssembly.instantiate(wasmBytes, {
            sealed_lattice_diagnostics: {
                monotonic_time_milliseconds: (): number => performance.now(),
            },
        });
        const wasmExports = instantiatedSource.instance.exports;
        const measurementFunction = resolveMeasurementFunction(wasmExports);
        const memory = resolveMemory(wasmExports);

        const firstWarmupChecksum = measurementFunction(
            measurement.warmupMultiplicationCount,
            measurement.seed,
        );
        const secondWarmupChecksum = measurementFunction(
            measurement.warmupMultiplicationCount,
            measurement.seed,
        );
        if (firstWarmupChecksum !== secondWarmupChecksum) {
            throw new Error(
                'The scalar WebAssembly field measurement is nondeterministic.',
            );
        }

        const linearMemoryByteLengthBeforeMeasurement =
            memory.buffer.byteLength;
        const startTimeMilliseconds = performance.now();
        const checksum = measurementFunction(
            measurement.multiplicationCount,
            measurement.seed,
        );
        const elapsedMilliseconds = performance.now() - startTimeMilliseconds;
        const linearMemoryByteLengthAfterMeasurement = memory.buffer.byteLength;
        if (
            linearMemoryByteLengthAfterMeasurement >
            foundationProfile.maximumWasmMemoryByteLength
        ) {
            throw new Error(
                `The scalar WebAssembly measurement used ${linearMemoryByteLengthAfterMeasurement} bytes of linear memory; absolute maximum is ${foundationProfile.maximumWasmMemoryByteLength}.`,
            );
        }

        const result = Object.freeze({
            schemaVersion: 1,
            measurementId: measurement.measurementId,
            evidenceClassification: measurement.evidenceClassification,
            environment: Object.freeze({
                architecture: process.arch,
                nodeVersion: process.version,
                platform: process.platform,
                scalarBuild: true,
                simdRequired: false,
                singleWorker: true,
            }),
            field: Object.freeze({
                canonicalByteLength: 40,
                modulusPolynomial: 'x^320 + x^117 + x^86 + x^21 + 1',
            }),
            build: Object.freeze({
                normalizedSha256Hex: builtArtifact.normalizedSha256Hex,
                wasmByteLength: wasmBytes.byteLength,
                exports: Object.keys(wasmExports).sort(),
            }),
            execution: Object.freeze({
                checksumUnsignedHex: unsignedWordHex(checksum),
                elapsedMilliseconds,
                linearMemoryByteLengthAfterMeasurement,
                linearMemoryByteLengthBeforeMeasurement,
                multiplicationCount: measurement.multiplicationCount,
                multiplicationsPerSecond:
                    measurement.multiplicationCount /
                    (elapsedMilliseconds / 1_000),
                seedUnsignedHex: unsignedWordHex(measurement.seed),
                warmupChecksumUnsignedHex: unsignedWordHex(firstWarmupChecksum),
                warmupMultiplicationCount:
                    measurement.warmupMultiplicationCount,
            }),
            limitation:
                'Node scalar WebAssembly development evidence only; not a complete preparation, browser, or supported-phone result.',
        });

        await mkdir(path.dirname(parsedArguments.outputFilePath), {
            recursive: true,
        });
        await writeFile(
            parsedArguments.outputFilePath,
            `${JSON.stringify(result, undefined, 4)}\n`,
            'utf8',
        );
        console.log(JSON.stringify(result));
    } finally {
        await rm(temporaryDirectoryPath, { force: true, recursive: true });
    }
};

if (import.meta.main) {
    await runPreparationFieldWasmMeasurementWorker();
}
