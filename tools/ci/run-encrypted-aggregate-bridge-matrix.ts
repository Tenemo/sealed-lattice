import { mkdir } from 'node:fs/promises';

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
    const workerCount = requestedWorkerCount(mode);
    await mkdir(outputDirectory, { recursive: true });
    await writeArtifact(
        'aggregate-bridge-negative-suite-inventory.json',
        `${canonicalJson({ items: negativeInventory })}\n`,
    );
    await writeArtifact(
        'aggregate-bridge-negative-suite-inventory.md',
        negativeInventoryMarkdown(),
    );
    if (mode === 'shape') {
        const shapeRows = buildShapeConfigRows(variants);
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
        }

        return;
    }
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
    const sharedWitnessZeroKnowledgeProofVerified =
        proofRows.length > 0 &&
        proofRows.every((row) => row.status === 'passed');
    const bgvRandomnessBoundProofVerified =
        sharedWitnessZeroKnowledgeProofVerified &&
        proofRows.every((row) => row.proofByteLength > 0);
    const proofCoreStatus = {
        bgvRandomnessBoundProofVerified,
        bridgeClaimClosureVerified: false,
        fullM9MatrixDeferred: mode !== 'full',
        m9FocusedSubsetComplete:
            mode === 'focused' &&
            allRowsPassed &&
            allNegativesPassed &&
            sharedWitnessZeroKnowledgeProofVerified &&
            bgvRandomnessBoundProofVerified,
        sharedWitnessZeroKnowledgeProofVerified,
    };
    const closureLedger = {
        labels: {
            aggregateBridgeAggregateReadyFullMatrixLocalEvidence:
                allRowsPassed && mode === 'full',
            aggregateBridgeFocusedSubsetImplementationEvidence:
                allRowsPassed && allNegativesPassed && mode === 'focused',
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
            `Negative checks passed: ${allNegativesPassed ? 'yes' : 'no'}`,
            `aggregateBridgeRepresentative20x20ProofRowLocalEvidence: ${closureLedger.labels.aggregateBridgeRepresentative20x20ProofRowLocalEvidence ? 'true' : 'false'}`,
            `aggregateBridgeFocusedSubsetImplementationEvidence: ${closureLedger.labels.aggregateBridgeFocusedSubsetImplementationEvidence ? 'true' : 'false'}`,
            `aggregateBridgePrivateRelationFullMatrixLocalEvidence: ${closureLedger.labels.aggregateBridgePrivateRelationFullMatrixLocalEvidence ? 'true' : 'false'}`,
            `aggregateBridgeProofFullMatrixLocalEvidence: ${closureLedger.labels.aggregateBridgeProofFullMatrixLocalEvidence ? 'true' : 'false'}`,
            `aggregateBridgeAggregateReadyFullMatrixLocalEvidence: ${closureLedger.labels.aggregateBridgeAggregateReadyFullMatrixLocalEvidence ? 'true' : 'false'}`,
            `aggregateBridgeScopedRelationFullMatrixLocalEvidence: ${closureLedger.labels.aggregateBridgeScopedRelationFullMatrixLocalEvidence ? 'true' : 'false'}`,
            `sharedWitnessZeroKnowledgeProofVerified: ${proofCoreStatus.sharedWitnessZeroKnowledgeProofVerified ? 'true' : 'false'}`,
            `bgvRandomnessBoundProofVerified: ${proofCoreStatus.bgvRandomnessBoundProofVerified ? 'true' : 'false'}`,
            `M9 focused subset complete: ${proofCoreStatus.m9FocusedSubsetComplete ? 'true' : 'false'}`,
            `M9 full matrix deferred: ${proofCoreStatus.fullM9MatrixDeferred ? 'true' : 'false'}`,
            `bridgeClaimClosureVerified: ${proofCoreStatus.bridgeClaimClosureVerified ? 'true' : 'false'}`,
            '',
        ].join('\n'),
    );
    if (!allRowsPassed || !allNegativesPassed) {
        process.exitCode = 1;
    }
};

await main();
