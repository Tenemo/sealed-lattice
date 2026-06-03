import { mkdir } from 'node:fs/promises';
import path from 'node:path';

import {
    negativeInventory,
    negativeInventoryMarkdown,
} from './encrypted-aggregate-bridge-matrix/negative-inventory.js';
import {
    appendVariantResult,
    matrixMarkdown,
    negativeMarkdown,
    shapeConfigMarkdown,
    writeArtifact,
} from './encrypted-aggregate-bridge-matrix/reporting.js';
import { buildShapeConfigRows } from './encrypted-aggregate-bridge-matrix/shape-config-checks.js';
import {
    matrixMode,
    outputDirectory,
    requestedWorkerCount,
    sentinelVariants,
    variantKey,
    variantsForMode,
    type MatrixRow,
    type NegativeCheck,
} from './encrypted-aggregate-bridge-matrix/shared.js';
import {
    runParallelVariantBuilds,
    runWorkerRow,
} from './encrypted-aggregate-bridge-matrix/workers.js';
import {
    createLocalRunLog,
    currentProcessExitCode,
    installProcessOutputLogTee,
    runLogDisabledByArguments,
} from './local-run-log.js';
import {
    createPackageManagerCommand,
    resolvePackageManagerRunner,
    runCommandsInSeries,
} from './run-command.js';

import { canonicalJson } from '#packages/crypto/src/index';

const rowVariantKeys = (rows: readonly MatrixRow[]): Set<string> =>
    new Set(
        rows.map((row) =>
            variantKey({
                optionCount: row.optionCount,
                rosterSize: row.rosterSize,
            }),
        ),
    );

const missingVariantKeys = (
    expectedKeys: readonly string[],
    observedKeys: ReadonlySet<string>,
): readonly string[] => expectedKeys.filter((key) => !observedKeys.has(key));

const rowFailureCount = (rows: readonly MatrixRow[]): number =>
    rows.filter((row) => row.status !== 'passed').length;

const negativeFailureCount = (checks: readonly NegativeCheck[]): number =>
    checks.filter((check) => !check.expectedFailureObserved).length;

const matrixScriptName = (mode: ReturnType<typeof matrixMode>): string =>
    mode === 'representative'
        ? 'test:encrypted-aggregate-bridge:representative'
        : 'test:encrypted-aggregate-bridge';

const main = async (): Promise<void> => {
    if (await runWorkerRow()) {
        return;
    }

    const rawArguments = process.argv.slice(2);
    const mode = matrixMode();
    const runLog = runLogDisabledByArguments(rawArguments)
        ? undefined
        : await createLocalRunLog({
              commandLineArguments: rawArguments,
              lanes: [mode],
              scriptName: matrixScriptName(mode),
          });
    let restoreOutput: (() => void) | undefined;

    try {
        const packageManagerRunner = resolvePackageManagerRunner();
        const buildExitCode = await runCommandsInSeries(
            [
                createPackageManagerCommand(
                    'Build workspace packages',
                    ['run', 'build'],
                    {
                        logFileSlug: 'build',
                        packageManagerRunner,
                    },
                ),
            ],
            { runLog },
        );
        if (buildExitCode !== 0) {
            process.exitCode = buildExitCode;

            return;
        }
        restoreOutput =
            runLog === undefined
                ? undefined
                : installProcessOutputLogTee(runLog);

        const variants = variantsForMode(mode);
        await mkdir(outputDirectory, { recursive: true });
        await writeArtifact(
            'aggregate-bridge-negative-suite-inventory.json',
            `${canonicalJson({ items: negativeInventory })}\n`,
        );
        await writeArtifact(
            'aggregate-bridge-negative-suite-inventory.md',
            negativeInventoryMarkdown(),
        );

        if (mode === 'full') {
            const shapeRows = buildShapeConfigRows(variantsForMode('full'));
            const shapeRowsPassed = shapeRows.every(
                (row) => row.status === 'passed',
            );
            await writeArtifact(
                'aggregate-bridge-shape-config-matrix.json',
                `${canonicalJson({
                    mode,
                    requiredFullMatrixRowCount: 342,
                    rows: shapeRows,
                    rowsPassed: shapeRowsPassed,
                })}\n`,
            );
            await writeArtifact(
                'aggregate-bridge-shape-config-matrix.md',
                shapeConfigMarkdown(shapeRows),
            );
            if (!shapeRowsPassed) {
                process.exitCode = 1;

                return;
            }
        }

        const workerCount = requestedWorkerCount(mode);
        const privateRows: MatrixRow[] = [];
        const proofRows: MatrixRow[] = [];
        const aggregateReadyRows: MatrixRow[] = [];
        const benchmarkRows: MatrixRow[] = [];
        const negativeChecks: NegativeCheck[] = [];
        const variantResults = await runParallelVariantBuilds({
            variants,
            workerCount,
            workerLogDirectoryPath:
                runLog === undefined
                    ? undefined
                    : path.join(runLog.runDirectoryPath, 'workers'),
        });
        for (const result of variantResults) {
            appendVariantResult({
                aggregateReadyRows,
                benchmarkRows,
                negativeChecks,
                privateRows,
                proofRows,
                result,
            });
        }
        const expectedRowCount = variants.length;
        const requiredVariantKeys = variants.map(variantKey);
        const privateRowKeys = rowVariantKeys(privateRows);
        const proofRowKeys = rowVariantKeys(proofRows);
        const aggregateReadyRowKeys = rowVariantKeys(aggregateReadyRows);
        const missingPrivateRowKeys = missingVariantKeys(
            requiredVariantKeys,
            privateRowKeys,
        );
        const missingProofRowKeys = missingVariantKeys(
            requiredVariantKeys,
            proofRowKeys,
        );
        const missingAggregateReadyRowKeys = missingVariantKeys(
            requiredVariantKeys,
            aggregateReadyRowKeys,
        );
        const matrixRowCountsPassed =
            privateRows.length === expectedRowCount &&
            proofRows.length === expectedRowCount &&
            missingPrivateRowKeys.length === 0 &&
            missingProofRowKeys.length === 0;
        const cheapNegativeVariantKeys = new Set(
            negativeChecks
                .filter((check) => check.suite === 'cheap')
                .map((check) =>
                    variantKey({
                        optionCount: check.optionCount,
                        rosterSize: check.rosterSize,
                    }),
                ),
        );
        const sentinelVariantKeysForMode = requiredVariantKeys.filter((key) =>
            sentinelVariants.has(key),
        );
        const sentinelNegativeVariantKeys = new Set(
            negativeChecks
                .filter((check) => check.suite === 'sentinel')
                .map((check) =>
                    variantKey({
                        optionCount: check.optionCount,
                        rosterSize: check.rosterSize,
                    }),
                ),
        );
        const missingCheapNegativeVariantKeys = missingVariantKeys(
            requiredVariantKeys,
            cheapNegativeVariantKeys,
        );
        const missingSentinelNegativeVariantKeys = missingVariantKeys(
            sentinelVariantKeysForMode,
            sentinelNegativeVariantKeys,
        );
        const negativeCoveragePassed =
            missingCheapNegativeVariantKeys.length === 0 &&
            missingSentinelNegativeVariantKeys.length === 0;
        console.log(
            [
                'Encrypted aggregate bridge row summary:',
                `expected=${expectedRowCount}`,
                `privateRows=${privateRows.length}`,
                `privateFailures=${rowFailureCount(privateRows)}`,
                `proofRows=${proofRows.length}`,
                `proofFailures=${rowFailureCount(proofRows)}`,
                `aggregateReadyRows=${aggregateReadyRows.length}`,
                `aggregateReadyFailures=${rowFailureCount(aggregateReadyRows)}`,
                `negativeChecks=${negativeChecks.length}`,
                `negativeFailures=${negativeFailureCount(negativeChecks)}`,
                `missingCheapNegativeRows=${missingCheapNegativeVariantKeys.length}`,
                `missingSentinelNegativeRows=${missingSentinelNegativeVariantKeys.length}`,
            ].join(' '),
        );
        const slowestRow = [...proofRows]
            .filter((row) => row.status === 'passed')
            .sort((left, right) => right.proverTime - left.proverTime)[0];
        const benchmarkRowsByVariant = new Map(
            benchmarkRows.map((row) => [
                variantKey({
                    optionCount: row.optionCount,
                    rosterSize: row.rosterSize,
                }),
                row,
            ]),
        );
        if (slowestRow !== undefined) {
            benchmarkRowsByVariant.set(
                variantKey({
                    optionCount: slowestRow.optionCount,
                    rosterSize: slowestRow.rosterSize,
                }),
                slowestRow,
            );
        }
        const finalBenchmarkRows = [...benchmarkRowsByVariant.values()];
        const allRowsPassed =
            matrixRowCountsPassed &&
            proofRows.every((row) => row.status === 'passed') &&
            privateRows.every((row) => row.status === 'passed');
        const allAggregateReadyRowsPassed =
            aggregateReadyRows.length === expectedRowCount &&
            missingAggregateReadyRowKeys.length === 0 &&
            aggregateReadyRows.every((row) => row.status === 'passed');
        const allNegativesPassed =
            negativeCoveragePassed &&
            negativeChecks.every((check) => check.expectedFailureObserved);
        const sharedWitnessZeroKnowledgeProofVerified =
            proofRows.length > 0 &&
            proofRows.every((row) => row.status === 'passed');
        const bgvRandomnessBoundProofVerified =
            sharedWitnessZeroKnowledgeProofVerified &&
            proofRows.every((row) => row.proofByteLength > 0);
        const proofCoreStatus = {
            bgvRandomnessBoundProofVerified,
            bridgeClaimClosureVerified: false,
            fullBridgeMatrixDeferred: mode !== 'full',
            sharedWitnessZeroKnowledgeProofVerified,
        };
        const closureLedger = {
            expectedRowCount,
            labels: {
                aggregateBridgeAggregateReadyFullMatrixLocalEvidence:
                    allAggregateReadyRowsPassed && mode === 'full',
                aggregateBridgePrivateRelationFullMatrixLocalEvidence:
                    allRowsPassed && mode === 'full',
                aggregateBridgeProofFullMatrixLocalEvidence:
                    allRowsPassed && mode === 'full',
                aggregateBridgeRepresentative20x20ProofRowLocalEvidence:
                    proofRows.some(
                        (row) =>
                            row.rosterSize === 20 &&
                            row.optionCount === 20 &&
                            row.status === 'passed',
                    ),
                aggregateBridgeScopedRelationFullMatrixLocalEvidence:
                    allRowsPassed && allNegativesPassed && mode === 'full',
            },
            matrixRowCountsPassed,
            missingAggregateReadyRowKeys,
            missingCheapNegativeVariantKeys,
            missingPrivateRowKeys,
            missingProofRowKeys,
            missingSentinelNegativeVariantKeys,
            mode,
            negativeChecksPassed: allNegativesPassed,
            negativeCoveragePassed,
            proofCoreStatus,
            rowCount: proofRows.length,
            rowsPassed: allRowsPassed,
            requiredFullMatrixRowCount: 342,
        };

        await writeArtifact(
            'aggregate-bridge-private-relation-variant-matrix.json',
            `${canonicalJson({ mode, rows: privateRows })}\n`,
        );
        await writeArtifact(
            'aggregate-bridge-private-relation-variant-matrix.md',
            matrixMarkdown({
                rows: privateRows,
                title: 'Encrypted aggregate bridge private relation variant matrix',
            }),
        );
        await writeArtifact(
            'aggregate-bridge-proof-variant-matrix.json',
            `${canonicalJson({ mode, rows: proofRows })}\n`,
        );
        await writeArtifact(
            'aggregate-bridge-proof-variant-matrix.md',
            matrixMarkdown({
                rows: proofRows,
                title: 'Encrypted aggregate bridge proof variant matrix',
            }),
        );
        await writeArtifact(
            'aggregate-bridge-ready-record-variant-matrix.json',
            `${canonicalJson({ mode, rows: aggregateReadyRows })}\n`,
        );
        await writeArtifact(
            'aggregate-bridge-ready-record-variant-matrix.md',
            matrixMarkdown({
                rows: aggregateReadyRows,
                title: 'Encrypted aggregate bridge aggregate-ready variant matrix',
            }),
        );
        await writeArtifact(
            'aggregate-bridge-negative-fixture-report.json',
            `${canonicalJson({ checks: negativeChecks, mode })}\n`,
        );
        await writeArtifact(
            'aggregate-bridge-negative-fixture-report.md',
            negativeMarkdown(negativeChecks),
        );
        await writeArtifact(
            'aggregate-bridge-benchmark-report.json',
            `${canonicalJson({ mode, rows: finalBenchmarkRows })}\n`,
        );
        await writeArtifact(
            'aggregate-bridge-benchmark-report.md',
            matrixMarkdown({
                rows: finalBenchmarkRows,
                title: 'Encrypted aggregate bridge benchmark report',
            }),
        );
        await writeArtifact(
            'aggregate-bridge-local-evidence-ledger.json',
            `${canonicalJson(closureLedger)}\n`,
        );
        await writeArtifact(
            'aggregate-bridge-local-evidence-ledger.md',
            [
                '# Encrypted aggregate bridge local evidence ledger',
                '',
                `Mode: ${mode}`,
                `Rows passed: ${allRowsPassed ? 'yes' : 'no'}`,
                `Matrix row counts passed: ${matrixRowCountsPassed ? 'yes' : 'no'}`,
                `Negative checks passed: ${allNegativesPassed ? 'yes' : 'no'}`,
                `Negative coverage passed: ${negativeCoveragePassed ? 'yes' : 'no'}`,
                `aggregateBridgeRepresentative20x20ProofRowLocalEvidence: ${closureLedger.labels.aggregateBridgeRepresentative20x20ProofRowLocalEvidence ? 'true' : 'false'}`,
                `aggregateBridgePrivateRelationFullMatrixLocalEvidence: ${closureLedger.labels.aggregateBridgePrivateRelationFullMatrixLocalEvidence ? 'true' : 'false'}`,
                `aggregateBridgeProofFullMatrixLocalEvidence: ${closureLedger.labels.aggregateBridgeProofFullMatrixLocalEvidence ? 'true' : 'false'}`,
                `aggregateBridgeAggregateReadyFullMatrixLocalEvidence: ${closureLedger.labels.aggregateBridgeAggregateReadyFullMatrixLocalEvidence ? 'true' : 'false'}`,
                `aggregateBridgeScopedRelationFullMatrixLocalEvidence: ${closureLedger.labels.aggregateBridgeScopedRelationFullMatrixLocalEvidence ? 'true' : 'false'}`,
                `sharedWitnessZeroKnowledgeProofVerified: ${proofCoreStatus.sharedWitnessZeroKnowledgeProofVerified ? 'true' : 'false'}`,
                `bgvRandomnessBoundProofVerified: ${proofCoreStatus.bgvRandomnessBoundProofVerified ? 'true' : 'false'}`,
                `Full bridge matrix deferred: ${proofCoreStatus.fullBridgeMatrixDeferred ? 'true' : 'false'}`,
                `bridgeClaimClosureVerified: ${proofCoreStatus.bridgeClaimClosureVerified ? 'true' : 'false'}`,
                '',
            ].join('\n'),
        );
        if (!allRowsPassed || !allNegativesPassed) {
            process.exitCode = 1;
        }
    } catch (error) {
        process.exitCode = 1;
        throw error;
    } finally {
        restoreOutput?.();
        await runLog?.finish({ exitCode: currentProcessExitCode() });
    }
};

await main();
