import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { protocolHashNamespaceValues } from '#packages/types/src/protocol-hash';

const workspaceRoot = process.cwd();
const typeScriptRegistryRelativePath = path.normalize(
    'packages/types/src/protocol-hash.ts',
);
const rustRegistryRelativePath = path.normalize(
    'crates/sealed-lattice-kernel/src/hashing/mod.rs',
);
const sourceRootDirectoryNames = ['packages', 'crates'] as const;
const scannedSourceFileExtensions = new Set(['.rs', '.ts', '.tsx']);
const ignoredPathSegmentPattern =
    /(?:^|[\\/])(?:coverage|dist|node_modules|target|temp)(?:[\\/]|$)/u;
const reusedNamespaceValues = [
    'ChallengeDomainHash',
    'ConflictingHeadEvidenceHash',
    'FirstValidOrderHash',
    'WitnessEquivocationEvidenceHash',
] as const;
type SourceFile = {
    readonly relativePath: string;
    readonly text: string;
};

const toPosixPath = (filePath: string): string => filePath.replace(/\\/gu, '/');

const readWorkspaceText = (relativePath: string): string =>
    readFileSync(path.join(workspaceRoot, relativePath), 'utf8');

const collectSourceRelativePaths = (
    directoryPath: string,
): readonly string[] => {
    const collectedPaths: string[] = [];

    for (const entry of readdirSync(directoryPath, { withFileTypes: true })) {
        const entryPath = path.join(directoryPath, entry.name);
        const relativePath = path.relative(workspaceRoot, entryPath);

        if (ignoredPathSegmentPattern.test(relativePath)) {
            continue;
        }
        if (entry.isDirectory()) {
            collectedPaths.push(...collectSourceRelativePaths(entryPath));
            continue;
        }
        if (
            entry.isFile() &&
            scannedSourceFileExtensions.has(path.extname(entry.name)) &&
            relativePath.includes(`${path.sep}src${path.sep}`)
        ) {
            collectedPaths.push(relativePath);
        }
    }

    return collectedPaths;
};

const loadProductionSourceFiles = (): readonly SourceFile[] =>
    sourceRootDirectoryNames
        .flatMap((sourceRootDirectoryName) =>
            collectSourceRelativePaths(
                path.join(workspaceRoot, sourceRootDirectoryName),
            ),
        )
        .filter(
            (relativePath) =>
                relativePath !== typeScriptRegistryRelativePath &&
                relativePath !== rustRegistryRelativePath,
        )
        .map((relativePath) => ({
            relativePath: toPosixPath(relativePath),
            text: readWorkspaceText(relativePath),
        }));

const quotedNamespacePattern = (namespace: string): RegExp =>
    new RegExp(`["']${namespace}["']`, 'u');

const pascalCaseToKebabCase = (value: string): string =>
    value
        .replace(/([A-Z]+)([A-Z][a-z])/gu, '$1-$2')
        .replace(/([a-z0-9])([A-Z])/gu, '$1-$2')
        .toLowerCase();

const namespaceDomain = (namespace: string): string =>
    `sealed-lattice-root/${pascalCaseToKebabCase(namespace)}-v1`;

const hasQuotedNamespace = (
    sourceFile: SourceFile,
    namespace: string,
): boolean =>
    quotedNamespacePattern(namespace).test(sourceFile.text) ||
    sourceFile.text.includes(namespaceDomain(namespace));

const lineNumberAt = (text: string, characterIndex: number): number =>
    text.slice(0, characterIndex).split(/\r?\n/u).length;

const collectQuotedNamespaceLocations = (
    sourceFile: SourceFile,
    namespace: string,
): readonly number[] => {
    const locations: number[] = [];
    const pattern = quotedNamespacePattern(namespace);
    let searchOffset = 0;

    while (searchOffset < sourceFile.text.length) {
        const match = pattern.exec(sourceFile.text.slice(searchOffset));

        if (match === null) {
            break;
        }

        const characterIndex = searchOffset + match.index;
        locations.push(characterIndex);
        searchOffset = characterIndex + match[0].length;
    }

    return locations;
};

describe('protocol hash registry guard', () => {
    const productionSourceFiles = loadProductionSourceFiles();

    it('keeps every reserved namespace backed by source code', () => {
        const missingSourceNamespaces = protocolHashNamespaceValues.filter(
            (namespace) =>
                !productionSourceFiles.some((sourceFile) =>
                    hasQuotedNamespace(sourceFile, namespace),
                ),
        );

        expect(missingSourceNamespaces).toEqual([]);
    });

    it('keeps reused source namespaces explicitly purpose-bound', () => {
        const unboundLocations = productionSourceFiles.flatMap((sourceFile) =>
            reusedNamespaceValues.flatMap((namespace) =>
                collectQuotedNamespaceLocations(sourceFile, namespace)
                    .filter((characterIndex) => {
                        const searchStart = Math.max(0, characterIndex - 2500);
                        const searchEnd = Math.min(
                            sourceFile.text.length,
                            characterIndex + 2500,
                        );

                        return !sourceFile.text
                            .slice(searchStart, searchEnd)
                            .includes('purpose');
                    })
                    .map(
                        (characterIndex) =>
                            `${sourceFile.relativePath}:${String(
                                lineNumberAt(sourceFile.text, characterIndex),
                            )}:${namespace}`,
                    ),
            ),
        );

        expect(unboundLocations).toEqual([]);
    });
});
