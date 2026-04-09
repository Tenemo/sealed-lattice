import { access, readFile } from 'node:fs/promises';
import path from 'node:path';

import {
    createCoverageArtifacts,
    type CoverageSummary,
    type ShieldsBadge,
} from './generate-coverage-badge';

const repoRoot = process.cwd();
const docsDistRoot = path.resolve(repoRoot, 'docs/dist');
const requiredDocsOutputs = [
    'index.html',
    'coverage-badge.json',
    'coverage-summary.json',
] as const;
const coverageBadgeOutput = 'coverage-badge.json';
const coverageSummaryOutput = 'coverage-summary.json';
const windowsAbsolutePathPattern = /^[A-Za-z]:\//;

const compareCoverageKeys = (leftKey: string, rightKey: string): number => {
    if (leftKey === 'total') {
        return -1;
    }
    if (rightKey === 'total') {
        return 1;
    }

    return leftKey.localeCompare(rightKey);
};

const readJsonFile = async <T>(filePath: string): Promise<T> =>
    JSON.parse(await readFile(filePath, 'utf8')) as T;

const isAbsoluteCoverageKey = (key: string): boolean =>
    path.posix.isAbsolute(key) ||
    path.win32.isAbsolute(key) ||
    windowsAbsolutePathPattern.test(key);

const main = async (): Promise<void> => {
    const failures: string[] = [];
    const missingOutputs = new Set<string>();

    for (const relativePath of requiredDocsOutputs) {
        const absolutePath = path.resolve(docsDistRoot, relativePath);
        try {
            await access(absolutePath);
        } catch {
            missingOutputs.add(relativePath);
            failures.push(
                `Missing docs build output: docs/dist/${relativePath}`,
            );
        }
    }

    const summaryPath = path.resolve(docsDistRoot, coverageSummaryOutput);
    const badgePath = path.resolve(docsDistRoot, coverageBadgeOutput);

    let summary: CoverageSummary | undefined;
    let badge: ShieldsBadge | undefined;

    try {
        summary = await readJsonFile<CoverageSummary>(summaryPath);
    } catch (error) {
        if (!missingOutputs.has(coverageSummaryOutput)) {
            const message =
                error instanceof Error ? error.message : String(error);
            failures.push(
                `Could not parse docs/dist/coverage-summary.json: ${message}`,
            );
        }
    }

    try {
        badge = await readJsonFile<ShieldsBadge>(badgePath);
    } catch (error) {
        if (!missingOutputs.has(coverageBadgeOutput)) {
            const message =
                error instanceof Error ? error.message : String(error);
            failures.push(
                `Could not parse docs/dist/coverage-badge.json: ${message}`,
            );
        }
    }

    if (summary !== undefined) {
        const actualKeys = Object.keys(summary);
        const expectedOrder = [...actualKeys].sort(compareCoverageKeys);

        if (actualKeys.join('\n') !== expectedOrder.join('\n')) {
            failures.push(
                'docs/dist/coverage-summary.json must keep "total" first and sort remaining coverage keys deterministically.',
            );
        }

        for (const key of actualKeys) {
            if (key === 'total') {
                continue;
            }

            if (key.includes('\\')) {
                failures.push(
                    `Coverage summary key contains backslashes: ${key}`,
                );
            }

            if (isAbsoluteCoverageKey(key)) {
                failures.push(
                    `Coverage summary key must be repo-relative, found absolute path: ${key}`,
                );
            }
        }

        try {
            const expectedArtifacts = createCoverageArtifacts(
                summary,
                repoRoot,
            );
            if (
                JSON.stringify(summary) !==
                JSON.stringify(expectedArtifacts.summary)
            ) {
                failures.push(
                    'docs/dist/coverage-summary.json does not match the normalized, sorted coverage artifact shape.',
                );
            }

            if (
                badge !== undefined &&
                JSON.stringify(badge) !==
                    JSON.stringify(expectedArtifacts.badge)
            ) {
                failures.push(
                    'docs/dist/coverage-badge.json does not match coverage-summary.json total line coverage.',
                );
            }
        } catch (error) {
            const message =
                error instanceof Error ? error.message : String(error);
            failures.push(message);
        }
    }

    if (failures.length > 0) {
        throw new Error(failures.join('\n'));
    }

    console.log('Docs build verification passed.');
};

void main();
