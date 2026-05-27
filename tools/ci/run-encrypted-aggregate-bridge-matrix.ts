import { mkdir } from 'node:fs/promises';

import {
    appendVariantResult,
    matrixMarkdown,
    negativeMarkdown,
    writeArtifact,
} from './encrypted-aggregate-bridge-matrix/reporting.js';
import {
    matrixMode,
    outputDirectory,
    requestedWorkerCount,
    variantKey,
    variantsForMode,
    type MatrixRow,
    type NegativeCheck,
} from './encrypted-aggregate-bridge-matrix/shared.js';
import {
    runParallelVariantBuilds,
    runSequentialVariantBuilds,
    runWorkerRow,
} from './encrypted-aggregate-bridge-matrix/workers.js';

import { canonicalJson } from '#packages/crypto/src/index';

const main = async (): Promise<void> => {
    if (await runWorkerRow()) {
        return;
    }

    const mode = matrixMode();
    const variants = variantsForMode(mode);
    const workerCount = requestedWorkerCount();
    await mkdir(outputDirectory, { recursive: true });
    const privateRows: MatrixRow[] = [];
    const proofRows: MatrixRow[] = [];
    const aggregateReadyRows: MatrixRow[] = [];
    const benchmarkRows: MatrixRow[] = [];
    const negativeChecks: NegativeCheck[] = [];
    const variantResults =
        workerCount <= 1
            ? await runSequentialVariantBuilds(variants)
            : await runParallelVariantBuilds({ variants, workerCount });
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
        proofRows.every((row) => row.status === 'passed') &&
        aggregateReadyRows.every((row) => row.status === 'passed') &&
        privateRows.every((row) => row.status === 'passed');
    const allNegativesPassed = negativeChecks.every(
        (check) => check.expectedFailureObserved,
    );
    const closureLedger = {
        labels: {
            aggregateBridgeAggregateReadyFullMatrixLocalEvidence:
                allRowsPassed && mode === 'full',
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
        mode,
        negativeChecksPassed: allNegativesPassed,
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
            `Negative checks passed: ${allNegativesPassed ? 'yes' : 'no'}`,
            `aggregateBridgeRepresentative20x20ProofRowLocalEvidence: ${closureLedger.labels.aggregateBridgeRepresentative20x20ProofRowLocalEvidence ? 'true' : 'false'}`,
            `aggregateBridgePrivateRelationFullMatrixLocalEvidence: ${closureLedger.labels.aggregateBridgePrivateRelationFullMatrixLocalEvidence ? 'true' : 'false'}`,
            `aggregateBridgeProofFullMatrixLocalEvidence: ${closureLedger.labels.aggregateBridgeProofFullMatrixLocalEvidence ? 'true' : 'false'}`,
            `aggregateBridgeAggregateReadyFullMatrixLocalEvidence: ${closureLedger.labels.aggregateBridgeAggregateReadyFullMatrixLocalEvidence ? 'true' : 'false'}`,
            `aggregateBridgeScopedRelationFullMatrixLocalEvidence: ${closureLedger.labels.aggregateBridgeScopedRelationFullMatrixLocalEvidence ? 'true' : 'false'}`,
            '',
        ].join('\n'),
    );
    if (!allRowsPassed || !allNegativesPassed) {
        process.exitCode = 1;
    }
};

await main();
