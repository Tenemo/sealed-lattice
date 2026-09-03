import { createHash } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';

export type SourceManifestRow = Readonly<{
    identifier: string;
    relativePath: string;
    byteLength: number;
    sha512Hex: string;
    lineNumber: number;
}>;

export type SourceManifestFailure = Readonly<{
    identifier: string;
    lineNumber: number;
    reason: string;
}>;

const backtickedCell = /^`([^`]+)`$/u;
const sha512Pattern = /^[0-9a-f]{128}$/u;

const unwrapBackticks = (cell: string, name: string, lineNumber: number) => {
    const match = backtickedCell.exec(cell.trim());
    if (match?.[1] === undefined) {
        throw new Error(
            `Manifest line ${String(lineNumber)}: ${name} must be wrapped in backticks.`,
        );
    }
    return match[1];
};

/**
 * Parses every source row of a manifest table. A source row starts with a
 * backticked identifier and carries path, byte length, SHA-512, and a note.
 * Header and separator rows are skipped; any other malformed row throws.
 */
export const parseSourceManifestRows = (
    markdown: string,
): readonly SourceManifestRow[] => {
    const rows: SourceManifestRow[] = [];
    const seenIdentifiers = new Set<string>();
    markdown.split(/\r?\n/u).forEach((line, index) => {
        const lineNumber = index + 1;
        if (!line.startsWith('| `')) return;
        const cells = line
            .slice(1, line.endsWith('|') ? -1 : undefined)
            .split(' | ');
        if (cells.length < 5) {
            throw new Error(
                `Manifest line ${String(lineNumber)}: expected five cells.`,
            );
        }
        const identifier = unwrapBackticks(
            cells[0] ?? '',
            'the identifier',
            lineNumber,
        );
        const relativePath = unwrapBackticks(
            cells[1] ?? '',
            'the path',
            lineNumber,
        );
        const byteText = (cells[2] ?? '').trim().replace(/,/gu, '');
        if (!/^\d+$/u.test(byteText)) {
            throw new Error(
                `Manifest line ${String(lineNumber)}: the byte length is not an integer.`,
            );
        }
        const sha512Hex = unwrapBackticks(
            cells[3] ?? '',
            'the SHA-512 digest',
            lineNumber,
        );
        if (!sha512Pattern.test(sha512Hex)) {
            throw new Error(
                `Manifest line ${String(lineNumber)}: the SHA-512 digest is malformed.`,
            );
        }
        if (seenIdentifiers.has(identifier)) {
            throw new Error(
                `Manifest line ${String(lineNumber)}: duplicate identifier ${identifier}.`,
            );
        }
        seenIdentifiers.add(identifier);
        rows.push({
            identifier,
            relativePath,
            byteLength: Number(byteText),
            sha512Hex,
            lineNumber,
        });
    });
    return rows;
};

/**
 * Verifies that every manifest row names an existing file whose length and
 * SHA-512 digest match. Failures are collected rather than thrown so one run
 * reports every stale row.
 */
export const verifySourceManifest = async (
    markdown: string,
    rootDirectory: string,
): Promise<
    Readonly<{
        verifiedCount: number;
        failures: readonly SourceManifestFailure[];
    }>
> => {
    const rows = parseSourceManifestRows(markdown);
    const failures: SourceManifestFailure[] = [];
    for (const row of rows) {
        const filePath = path.resolve(rootDirectory, row.relativePath);
        let byteLength: number;
        try {
            byteLength = (await stat(filePath)).size;
        } catch {
            failures.push({
                identifier: row.identifier,
                lineNumber: row.lineNumber,
                reason: 'the pinned file is missing',
            });
            continue;
        }
        if (byteLength !== row.byteLength) {
            failures.push({
                identifier: row.identifier,
                lineNumber: row.lineNumber,
                reason: `the file has ${String(byteLength)} bytes, not ${String(row.byteLength)}`,
            });
            continue;
        }
        const digest = createHash('sha512')
            .update(await readFile(filePath))
            .digest('hex');
        if (digest !== row.sha512Hex) {
            failures.push({
                identifier: row.identifier,
                lineNumber: row.lineNumber,
                reason: 'the SHA-512 digest differs',
            });
        }
    }
    return { verifiedCount: rows.length - failures.length, failures };
};

const usage =
    'Usage: verify-source-manifest.ts --manifest <file> --root <directory>';

const main = async (): Promise<void> => {
    const argumentsList = process.argv.slice(2);
    if (
        argumentsList.length !== 4 ||
        argumentsList[0] !== '--manifest' ||
        argumentsList[1] === undefined ||
        argumentsList[2] !== '--root' ||
        argumentsList[3] === undefined
    ) {
        throw new Error(usage);
    }
    const markdown = await readFile(path.resolve(argumentsList[1]), 'utf8');
    const result = await verifySourceManifest(
        markdown,
        path.resolve(argumentsList[3]),
    );
    for (const failure of result.failures) {
        process.stdout.write(
            `line ${String(failure.lineNumber)} ${failure.identifier}: ${failure.reason}\n`,
        );
    }
    process.stdout.write(
        `Verified ${String(result.verifiedCount)} pinned sources; ${String(result.failures.length)} failures.\n`,
    );
    if (result.failures.length > 0) process.exitCode = 1;
};

if (import.meta.main) await main();
