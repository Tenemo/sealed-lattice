import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';

import binaryen from 'binaryen';

import { runWithLocalRunLog } from '#tools/ci/local-run-log.js';
import { runCommandAndCaptureOutput } from '#tools/ci/run-command.js';

// Compares the encrypted arithmetic's transforms with pointwise products on
// its current 58-bit primes with the same work on primes below 2^31 that
// cover the same tensor bound, on one thread natively and in scalar
// WebAssembly under Node, after checking that every width computes the
// same products. A narrower width meets the planned threshold under an
// engine when its negacyclic products run at least 1.5 times as fast as the
// current ones at both the smallest and the largest ciphertext modulus.

const threshold = 1.5;
const repetitions = 9;
const seed = 20_261_002n;
const widths = ['current-58', 'lazy-30', 'reduced-31'] as const;
const kernels = ['forward', 'backward', 'product', 'tensor'] as const;
const root = path.resolve('.');
const crate = path.join(
    root,
    'crates/protocol-research/arithmetic-width-benchmark',
);
const targetDirectory = path.join(root, 'target', 'arithmetic-width-benchmark');

type Kernel = (typeof kernels)[number];
type WidthTiming = {
    width: string;
    primes: number;
    digest: string;
    milliseconds: Record<Kernel, number[]>;
};
type TimingReport = {
    repetitions: number;
    seed: number;
    moduli: { largest: boolean; widths: WidthTiming[] }[];
};
type BenchmarkExports = {
    benchmark_prepare(width: number, largest: number, seed: bigint): number;
    benchmark_run(width: number, kernel: number): number;
    benchmark_digest(width: number): bigint;
    benchmark_release(): void;
};

const median = (values: readonly number[]) => {
    const sorted = [...values].sort((left, right) => left - right);
    const middle = sorted.length >> 1;
    return sorted.length % 2 === 1
        ? sorted[middle]
        : (sorted[middle - 1] + sorted[middle]) / 2;
};

// Times each kernel of each width after two warm-up runs, alternating the
// widths as the native timing does.
const timeWebAssembly = async (
    module: Uint8Array<ArrayBuffer>,
): Promise<TimingReport> => {
    const instance = await WebAssembly.instantiate(
        await WebAssembly.compile(module),
    );
    const exports = instance.exports as unknown as BenchmarkExports;
    const moduli: TimingReport['moduli'] = [];
    for (const largest of [false, true]) {
        const counts = widths.map((_width, index) =>
            exports.benchmark_prepare(index, largest ? 1 : 0, seed),
        );
        assert.ok(counts.every((count) => count > 0));
        for (let width = 0; width < widths.length; width++)
            for (let kernel = 0; kernel < kernels.length; kernel++)
                for (let run = 0; run < 2; run++)
                    assert.equal(exports.benchmark_run(width, kernel), 0);
        const samples = widths.map(() => kernels.map((): number[] => []));
        for (let repetition = 0; repetition < repetitions; repetition++)
            for (let kernel = 0; kernel < kernels.length; kernel++)
                for (let offset = 0; offset < widths.length; offset++) {
                    const width = (repetition + offset) % widths.length;
                    const start = performance.now();
                    const refused = exports.benchmark_run(width, kernel);
                    samples[width][kernel].push(performance.now() - start);
                    assert.equal(refused, 0);
                }
        moduli.push({
            largest,
            widths: widths.map((width, index) => ({
                width,
                primes: counts[index],
                digest: BigInt.asUintN(64, exports.benchmark_digest(index))
                    .toString(16)
                    .padStart(16, '0'),
                milliseconds: {
                    forward: samples[index][0],
                    backward: samples[index][1],
                    product: samples[index][2],
                    tensor: samples[index][3],
                },
            })),
        });
        exports.benchmark_release();
    }
    return { repetitions, seed: Number(seed), moduli };
};

// The median of every kernel and its speedup over the current width.
const summarize = (report: TimingReport) =>
    report.moduli.map(({ largest, widths: timings }) => {
        const current = timings[0];
        return {
            largest,
            widths: timings.map((timing) => ({
                width: timing.width,
                primes: timing.primes,
                medianMilliseconds: Object.fromEntries(
                    kernels.map((kernel) => [
                        kernel,
                        median(timing.milliseconds[kernel]),
                    ]),
                ),
                speedup: Object.fromEntries(
                    kernels.map((kernel) => [
                        kernel,
                        median(current.milliseconds[kernel]) /
                            median(timing.milliseconds[kernel]),
                    ]),
                ),
            })),
        };
    });

// Whether a width's negacyclic products meet the threshold at every
// modulus.
const meetsThreshold = (report: TimingReport, width: string) =>
    report.moduli.every(({ widths: timings }) => {
        const timing = timings.find((candidate) => candidate.width === width);
        assert.ok(timing !== undefined);
        return (
            median(timings[0].milliseconds.tensor) /
                median(timing.milliseconds.tensor) >=
            threshold
        );
    });

const digests = (report: TimingReport) =>
    report.moduli.map(({ largest, widths: timings }) => ({
        largest,
        digests: timings.map(({ width, digest }) => ({ width, digest })),
    }));

const commandLineArguments = process.argv
    .slice(2)
    .filter((value) => value !== '--');
if (commandLineArguments.length !== 0)
    throw new Error('The arithmetic width benchmark takes no arguments.');

await runWithLocalRunLog(
    {
        commandLineArguments,
        lanes: [
            'Pinned benchmark build',
            'Native equivalence',
            'Native timing',
            'Scalar WebAssembly timing under Node',
        ],
        scriptName: 'research:arithmetic-width',
    },
    async (log) => {
        const {
            RUSTFLAGS: _flags,
            CARGO_ENCODED_RUSTFLAGS: _encodedFlags,
            ...inherited
        } = process.env;
        const environment: NodeJS.ProcessEnv = {
            ...inherited,
            CARGO_INCREMENTAL: '0',
            CARGO_TARGET_DIR: targetDirectory,
        };
        // The participant module's scalar code generation.
        const scalarEnvironment: NodeJS.ProcessEnv = {
            ...environment,
            CARGO_ENCODED_RUSTFLAGS: ['-C', 'target-feature=-simd128'].join(
                '\x1f',
            ),
        };
        const execute = async (
            command: string,
            args: string[],
            name: string,
            env = environment,
        ) => {
            const result = await runCommandAndCaptureOutput(
                {
                    command,
                    args,
                    env,
                    workingDirectoryPath: crate,
                    description: name,
                    logFileSlug: name,
                },
                {
                    runLog: log,
                    echoOutput: true,
                    signal: AbortSignal.timeout(1_800_000),
                },
            );
            assert.equal(result.exitCode, 0, name);
            assert.equal(result.terminationSignal, null, name);
            return result.stdout;
        };
        const cargo = ['+1.95.0'];
        const locked = ['--offline', '--locked'];
        const compiler = await execute('rustc', [...cargo, '-Vv'], 'compiler');
        assert.match(
            compiler,
            /commit-hash: 59807616e1fa2540724bfbac14d7976d7e4a3860/u,
        );
        await execute('cargo', [...cargo, 'fmt', '--', '--check'], 'format');
        await execute(
            'cargo',
            [
                ...cargo,
                'clippy',
                ...locked,
                '--all-targets',
                '--',
                '-D',
                'warnings',
            ],
            'clippy',
        );
        await execute(
            'cargo',
            [
                ...cargo,
                'clippy',
                ...locked,
                '--lib',
                '--target',
                'wasm32-unknown-unknown',
                '--',
                '-D',
                'warnings',
            ],
            'clippy-webassembly',
            scalarEnvironment,
        );
        await execute('cargo', [...cargo, 'test', ...locked], 'unit-tests');
        await execute(
            'cargo',
            [
                ...cargo,
                'build',
                ...locked,
                '--release',
                '--bin',
                'arithmetic-width-benchmark',
            ],
            'native-build',
        );
        const executable = path.join(
            targetDirectory,
            'release',
            'arithmetic-width-benchmark' +
                (process.platform === 'win32' ? '.exe' : ''),
        );
        const equivalence: unknown = JSON.parse(
            await execute(
                executable,
                ['check', String(seed)],
                'native-equivalence',
            ),
        );
        const native = JSON.parse(
            await execute(
                executable,
                ['time', String(repetitions), String(seed)],
                'native-timing',
            ),
        ) as TimingReport;
        await execute(
            'cargo',
            [
                ...cargo,
                'build',
                ...locked,
                '--release',
                '--lib',
                '--target',
                'wasm32-unknown-unknown',
            ],
            'webassembly-build',
            scalarEnvironment,
        );
        const module = new Uint8Array(
            await readFile(
                path.join(
                    targetDirectory,
                    'wasm32-unknown-unknown',
                    'release',
                    'arithmetic_width_benchmark.wasm',
                ),
            ),
        );
        const inspected = binaryen.readBinary(module);
        try {
            assert.doesNotMatch(
                inspected.emitText(),
                /\b(?:v128|i8x16|i16x8|i32x4|i64x2|f32x4|f64x2)\./u,
                'The benchmark module contains vector instructions.',
            );
        } finally {
            inspected.dispose();
        }
        assert.deepEqual(
            WebAssembly.Module.imports(await WebAssembly.compile(module)),
            [],
        );
        await mkdir(log.artifactDirectoryPath, { recursive: true });
        await writeFile(
            path.join(
                log.artifactDirectoryPath,
                'arithmetic_width_benchmark.wasm',
            ),
            module,
        );
        const node = await timeWebAssembly(module);
        // Every width computes the same outputs in both builds.
        assert.deepEqual(digests(node), digests(native));
        const result = {
            threshold,
            repetitions,
            seed: Number(seed),
            compiler: compiler
                .split(/\r?\n/u)
                .filter((line) => line.length > 0 && !line.startsWith('host: '))
                .join('\n'),
            nodeVersion: process.version,
            module: {
                bytes: module.length,
                sha256: createHash('sha256').update(module).digest('hex'),
            },
            equivalence,
            engines: {
                native: { summary: summarize(native), samples: native },
                node: { summary: summarize(node), samples: node },
            },
            meetsThreshold: Object.fromEntries(
                widths.slice(1).map((width) => [
                    width,
                    {
                        native: meetsThreshold(native, width),
                        node: meetsThreshold(node, width),
                    },
                ]),
            ),
            notMeasured: [
                'an external Chrome worker',
                'a keyed product with its lifts',
            ],
        };
        await writeFile(
            path.join(log.runDirectoryPath, 'result.json'),
            JSON.stringify(result, null, 4) + '\n',
        );
        for (const [engine, report] of [
            ['native', native],
            ['node', node],
        ] as const)
            for (const { largest, widths: timings } of summarize(report))
                for (const timing of timings.slice(1))
                    process.stdout.write(
                        `${engine} ${largest ? 'largest' : 'smallest'} modulus ${timing.width}: ` +
                            kernels
                                .map(
                                    (kernel) =>
                                        `${kernel} ${timing.speedup[kernel].toFixed(2)}x`,
                                )
                                .join(', ') +
                            '\n',
                    );
        process.stdout.write(
            `Result: ${path.join(log.runDirectoryPath, 'result.json')}\n`,
        );
    },
);
