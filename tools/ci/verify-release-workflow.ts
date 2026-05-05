import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const releaseArtifactName = 'release-package';
const expectedReleaseArtifactPaths = [
    'packages/sdk/package.json',
    'packages/sdk/dist',
] as const;

const getLeadingSpaceCount = (line: string): number => {
    const leadingSpaces = /^ */.exec(line)?.[0] ?? '';

    return leadingSpaces.length;
};

const splitTextIntoLines = (text: string): string[] => text.split(/\r?\n/);

const stripWrappingQuotes = (value: string): string => {
    if (
        (value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))
    ) {
        return value.slice(1, -1);
    }

    return value;
};

export const normalizeWorkflowPath = (workflowPath: string): string => {
    const normalizedPath = workflowPath
        .replace(/\\/g, '/')
        .replace(/^\.\/+/, '')
        .replace(/\/+$/, '');

    return normalizedPath === '' ? '.' : normalizedPath;
};

const splitNormalizedPathIntoSegments = (normalizedPath: string): string[] => {
    return normalizedPath === '.'
        ? []
        : normalizedPath.split('/').filter(Boolean);
};

const extractIndentedBlockLines = (
    text: string,
    headerLineText: string,
): string[] => {
    const lines = splitTextIntoLines(text);
    const headerLineIndex = lines.findIndex(
        (line) => line.trim() === headerLineText,
    );

    if (headerLineIndex === -1) {
        return [];
    }

    const headerIndent = getLeadingSpaceCount(lines[headerLineIndex]);
    const blockLines: string[] = [];

    for (
        let lineIndex = headerLineIndex + 1;
        lineIndex < lines.length;
        lineIndex += 1
    ) {
        const line = lines[lineIndex];
        const trimmedLine = line.trim();

        if (trimmedLine !== '' && getLeadingSpaceCount(line) <= headerIndent) {
            break;
        }

        blockLines.push(line);
    }

    return blockLines;
};

export const getReleaseWorkflowPath = (
    projectRoot: string = repoRoot,
): string => path.resolve(projectRoot, '.github', 'workflows', 'release.yml');

export const extractWorkflowJobBlock = (
    workflowText: string,
    jobName: string,
): string => {
    const lines = splitTextIntoLines(workflowText);
    const jobLineText = `    ${jobName}:`;
    const jobLineIndex = lines.findIndex((line) => line === jobLineText);

    if (jobLineIndex === -1) {
        throw new Error(`Release workflow is missing job ${jobName}.`);
    }

    let jobEndLineIndex = lines.length;

    for (
        let lineIndex = jobLineIndex + 1;
        lineIndex < lines.length;
        lineIndex += 1
    ) {
        const line = lines[lineIndex];
        const trimmedLine = line.trim();

        if (
            trimmedLine !== '' &&
            getLeadingSpaceCount(line) === 4 &&
            /^[A-Za-z0-9_-]+:$/.test(trimmedLine)
        ) {
            jobEndLineIndex = lineIndex;
            break;
        }
    }

    return lines.slice(jobLineIndex, jobEndLineIndex).join('\n');
};

export const extractStepBlocks = (jobBlock: string): string[] => {
    const stepLines = extractIndentedBlockLines(jobBlock, 'steps:');
    const candidateStepStartIndexes = stepLines
        .map((line, index) => ({
            index,
            indent: getLeadingSpaceCount(line),
            isStepStart: line.trim().startsWith('- '),
        }))
        .filter((candidate) => candidate.isStepStart);

    if (candidateStepStartIndexes.length === 0) {
        return [];
    }

    const stepIndent = Math.min(
        ...candidateStepStartIndexes.map((candidate) => candidate.indent),
    );
    const stepStartIndexes = candidateStepStartIndexes
        .filter((candidate) => candidate.indent === stepIndent)
        .map((candidate) => candidate.index);

    return stepStartIndexes.map((startIndex, index) => {
        const endIndex =
            index === stepStartIndexes.length - 1
                ? stepLines.length
                : stepStartIndexes[index + 1];

        return stepLines.slice(startIndex, endIndex).join('\n');
    });
};

export const extractWithScalarValue = (
    stepBlock: string,
    key: string,
): string | undefined => {
    const withLines = extractIndentedBlockLines(stepBlock, 'with:');

    for (const line of withLines) {
        const trimmedLine = line.trim();

        if (!trimmedLine.startsWith(`${key}:`)) {
            continue;
        }

        const value = trimmedLine.slice(key.length + 1).trim();

        if (value === '' || value === '|') {
            return undefined;
        }

        return stripWrappingQuotes(value);
    }

    return undefined;
};

export const extractWithListValues = (
    stepBlock: string,
    key: string,
): string[] => {
    const withLines = extractIndentedBlockLines(stepBlock, 'with:');

    for (let lineIndex = 0; lineIndex < withLines.length; lineIndex += 1) {
        const line = withLines[lineIndex];
        const trimmedLine = line.trim();

        if (!trimmedLine.startsWith(`${key}:`)) {
            continue;
        }

        const keyIndent = getLeadingSpaceCount(line);
        const keyValue = trimmedLine.slice(key.length + 1).trim();

        if (keyValue !== '|') {
            return keyValue === '' ? [] : [stripWrappingQuotes(keyValue)];
        }

        const listValues: string[] = [];

        for (
            let valueLineIndex = lineIndex + 1;
            valueLineIndex < withLines.length;
            valueLineIndex += 1
        ) {
            const valueLine = withLines[valueLineIndex];
            const trimmedValueLine = valueLine.trim();
            const valueIndent = getLeadingSpaceCount(valueLine);

            if (trimmedValueLine !== '' && valueIndent <= keyIndent) {
                break;
            }

            if (trimmedValueLine === '') {
                continue;
            }

            listValues.push(stripWrappingQuotes(trimmedValueLine));
        }

        return listValues;
    }

    return [];
};

export const findArtifactStepBlock = (
    jobBlock: string,
    usesReference: string,
    artifactName: string,
): string | undefined => {
    return extractStepBlocks(jobBlock).find((stepBlock) => {
        return (
            stepBlock.includes(`uses: ${usesReference}`) &&
            extractWithScalarValue(stepBlock, 'name') === artifactName
        );
    });
};

export const deriveArtifactArchiveRelativePaths = (
    artifactUploadPaths: readonly string[],
): string[] => {
    if (artifactUploadPaths.length === 0) {
        return [];
    }

    const normalizedUploadPaths = artifactUploadPaths.map(
        normalizeWorkflowPath,
    );
    const normalizedPathSegments = normalizedUploadPaths.map(
        splitNormalizedPathIntoSegments,
    );
    const firstPathSegments = normalizedPathSegments[0];
    const commonPrefixSegments: string[] = [];

    for (
        let segmentIndex = 0;
        segmentIndex < firstPathSegments.length;
        segmentIndex += 1
    ) {
        const segment = firstPathSegments[segmentIndex];
        const isSharedByEveryUploadPath = normalizedPathSegments.every(
            (pathSegments) => pathSegments[segmentIndex] === segment,
        );

        if (!isSharedByEveryUploadPath) {
            break;
        }

        commonPrefixSegments.push(segment);
    }

    return normalizedUploadPaths.map((normalizedUploadPath) => {
        const relativeSegments = splitNormalizedPathIntoSegments(
            normalizedUploadPath,
        ).slice(commonPrefixSegments.length);

        return relativeSegments.join('/');
    });
};

export const simulateDownloadedArtifactPaths = (
    artifactUploadPaths: readonly string[],
    downloadPath: string,
): string[] => {
    const normalizedDownloadPath = normalizeWorkflowPath(downloadPath);

    return deriveArtifactArchiveRelativePaths(artifactUploadPaths).map(
        (archiveRelativePath) => {
            if (normalizedDownloadPath === '.') {
                return archiveRelativePath;
            }

            return `${normalizedDownloadPath}/${archiveRelativePath}`;
        },
    );
};

export const findReleaseWorkflowContractFailures = (
    workflowText: string,
): string[] => {
    const failures: string[] = [];
    const expectedArtifactPaths = [...expectedReleaseArtifactPaths];
    let artifactUploadPaths: string[] = [];

    try {
        const prepareReleaseJobBlock = extractWorkflowJobBlock(
            workflowText,
            'prepare-release',
        );
        const uploadArtifactStepBlock = findArtifactStepBlock(
            prepareReleaseJobBlock,
            'actions/upload-artifact@v7.0.1',
            releaseArtifactName,
        );

        if (uploadArtifactStepBlock === undefined) {
            failures.push(
                `prepare-release is missing an upload-artifact step for ${releaseArtifactName}.`,
            );
        } else {
            artifactUploadPaths = extractWithListValues(
                uploadArtifactStepBlock,
                'path',
            ).map(normalizeWorkflowPath);

            if (artifactUploadPaths.length === 0) {
                failures.push(
                    `prepare-release does not declare any upload paths for ${releaseArtifactName}.`,
                );
            }

            for (const expectedArtifactPath of expectedArtifactPaths) {
                if (artifactUploadPaths.includes(expectedArtifactPath)) {
                    continue;
                }

                failures.push(
                    `prepare-release does not upload ${expectedArtifactPath} into ${releaseArtifactName}.`,
                );
            }
        }
    } catch (error) {
        failures.push(error instanceof Error ? error.message : String(error));
    }

    for (const jobName of ['push-release', 'publish-npm']) {
        try {
            const jobBlock = extractWorkflowJobBlock(workflowText, jobName);
            const downloadArtifactStepBlock = findArtifactStepBlock(
                jobBlock,
                'actions/download-artifact@v8.0.1',
                releaseArtifactName,
            );

            if (downloadArtifactStepBlock === undefined) {
                failures.push(
                    `${jobName} is missing a download-artifact step for ${releaseArtifactName}.`,
                );
                continue;
            }

            const downloadPath = extractWithScalarValue(
                downloadArtifactStepBlock,
                'path',
            );

            if (downloadPath === undefined) {
                failures.push(
                    `${jobName} does not declare a download path for ${releaseArtifactName}.`,
                );
                continue;
            }

            if (artifactUploadPaths.length === 0) {
                continue;
            }

            const downloadedArtifactPaths = simulateDownloadedArtifactPaths(
                artifactUploadPaths,
                downloadPath,
            );

            for (const expectedArtifactPath of expectedArtifactPaths) {
                if (downloadedArtifactPaths.includes(expectedArtifactPath)) {
                    continue;
                }

                failures.push(
                    `${jobName} downloads ${releaseArtifactName} to ${normalizeWorkflowPath(downloadPath)}, which would place it at ${downloadedArtifactPaths.join(', ')} instead of ${expectedArtifactPath}.`,
                );
            }
        } catch (error) {
            failures.push(
                error instanceof Error ? error.message : String(error),
            );
        }
    }

    return failures;
};

const loadReleaseWorkflowText = (): string =>
    readFileSync(getReleaseWorkflowPath(), 'utf8');

/* v8 ignore start */
const main = (): void => {
    const failures = findReleaseWorkflowContractFailures(
        loadReleaseWorkflowText(),
    );

    if (failures.length > 0) {
        throw new Error(failures.join('\n'));
    }

    console.log(
        `Release workflow verification passed for ${path.basename(repoRoot)}.`,
    );
};

const scriptEntryPoint = process.argv[1];
const isMainModule =
    scriptEntryPoint !== undefined &&
    import.meta.url === pathToFileURL(scriptEntryPoint).href;

if (isMainModule) {
    main();
}
/* v8 ignore stop */
