import { spawn } from 'node:child_process';
import path from 'node:path';

import { buildVariant } from './build-variant.js';
import { failedVariantResult } from './reporting.js';
import {
    argumentValue,
    parseVariantKey,
    variantKey,
    workerOutputPrefix,
    type IndexedVariantBuildResult,
    type Variant,
    type VariantBuildResult,
} from './shared.js';

import { canonicalJson } from '#packages/crypto/src/index';
import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';

const variantBuildResultPassed = (result: VariantBuildResult): boolean =>
    result.proofRow.status === 'passed' &&
    result.aggregateReadyRow.status === 'passed' &&
    result.privateRelationRow.status === 'passed' &&
    result.negativeChecks.every((check) => check.expectedFailureObserved);

export const runWorkerRow = async (): Promise<boolean> => {
    const workerRowKey = argumentValue('--worker-row');
    if (workerRowKey === null) {
        return false;
    }

    const variant = parseVariantKey(workerRowKey);
    const kernel = await loadTranscriptCoreKernel();
    const result = (() => {
        try {
            return buildVariant({ kernel, variant });
        } catch (error) {
            return failedVariantResult(variant, error);
        }
    })();
    console.log(`${workerOutputPrefix}${canonicalJson(result)}`);
    if (!variantBuildResultPassed(result)) {
        process.exitCode = 1;
    }

    return true;
};

const runVariantInChildProcess = async (
    variant: Variant,
): Promise<VariantBuildResult> =>
    new Promise((resolve) => {
        const packageManagerCli = process.env.npm_execpath;
        const scriptPath = path.resolve(
            process.cwd(),
            'tools',
            'ci',
            'run-encrypted-aggregate-bridge-matrix.ts',
        );
        const workerArguments =
            packageManagerCli === undefined || packageManagerCli.length === 0
                ? [
                      path.resolve(
                          process.cwd(),
                          'node_modules',
                          'tsx',
                          'dist',
                          'cli.mjs',
                      ),
                      scriptPath,
                      '--worker-row',
                      variantKey(variant),
                  ]
                : [
                      packageManagerCli,
                      'exec',
                      'tsx',
                      scriptPath,
                      '--worker-row',
                      variantKey(variant),
                  ];
        const childProcess = spawn(process.execPath, workerArguments, {
            cwd: process.cwd(),
            env: process.env,
            stdio: ['ignore', 'pipe', 'pipe'],
        });
        let standardOutput = '';
        let standardError = '';
        childProcess.stdout.setEncoding('utf8');
        childProcess.stderr.setEncoding('utf8');
        childProcess.stdout.on('data', (chunk: string) => {
            standardOutput += chunk;
        });
        childProcess.stderr.on('data', (chunk: string) => {
            standardError += chunk;
            process.stderr.write(chunk);
        });
        childProcess.on('error', (error) => {
            resolve(failedVariantResult(variant, error));
        });
        childProcess.on('close', (exitCode) => {
            const resultLine = standardOutput
                .split(/\r?\n/u)
                .find((line) => line.startsWith(workerOutputPrefix));
            if (resultLine === undefined) {
                resolve(
                    failedVariantResult(
                        variant,
                        `Encrypted aggregate bridge worker exited with code ${String(exitCode)} without row output. ${standardError.slice(-2000)}`,
                    ),
                );

                return;
            }

            try {
                resolve(
                    JSON.parse(
                        resultLine.slice(workerOutputPrefix.length),
                    ) as VariantBuildResult,
                );
            } catch (error) {
                resolve(failedVariantResult(variant, error));
            }
        });
    });

export const runParallelVariantBuilds = async (input: {
    readonly variants: readonly Variant[];
    readonly workerCount: number;
}): Promise<readonly IndexedVariantBuildResult[]> => {
    const results: IndexedVariantBuildResult[] = [];
    let nextVariantIndex = 0;
    const workerSlotCount = Math.min(input.workerCount, input.variants.length);
    await Promise.all(
        Array.from(
            { length: workerSlotCount },
            async (_unused, workerIndex) => {
                while (true) {
                    const variantIndex = nextVariantIndex;
                    nextVariantIndex += 1;
                    const variant = input.variants[variantIndex];
                    if (variant === undefined) {
                        break;
                    }
                    console.log(
                        `Encrypted aggregate bridge row started: n=${variant.rosterSize}, m=${variant.optionCount}, worker=${workerIndex + 1}`,
                    );
                    const result = await runVariantInChildProcess(variant);
                    results.push({ ...result, variantIndex });
                    console.log(
                        `Encrypted aggregate bridge row finished: n=${variant.rosterSize}, m=${variant.optionCount}, worker=${workerIndex + 1}, status=${result.proofRow.status}`,
                    );
                }
            },
        ),
    );

    return [...results].sort(
        (left, right) => left.variantIndex - right.variantIndex,
    );
};
