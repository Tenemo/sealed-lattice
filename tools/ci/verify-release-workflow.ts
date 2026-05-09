import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { parse } from 'yaml';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const releaseArtifactName = 'release-package';
const expectedReleaseArtifactPaths = [
    'packages/sdk/package.json',
    'packages/sdk/dist',
] as const;

type WorkflowStep = {
    uses?: unknown;
    with?: Record<string, unknown>;
};

type WorkflowJob = {
    steps?: unknown;
};

type ReleaseWorkflow = {
    jobs?: Record<string, WorkflowJob>;
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

const isWorkflowStep = (value: unknown): value is WorkflowStep =>
    isRecord(value);

const stripWrappingQuotes = (value: string): string => {
    if (
        (value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))
    ) {
        return value.slice(1, -1);
    }

    return value;
};

export const parseReleaseWorkflow = (workflowText: string): ReleaseWorkflow => {
    const parsedWorkflow = parse(workflowText) as unknown;

    if (!isRecord(parsedWorkflow)) {
        throw new Error('Release workflow YAML must parse to an object.');
    }

    const jobs = parsedWorkflow.jobs;
    if (!isRecord(jobs)) {
        throw new Error('Release workflow is missing a jobs object.');
    }

    return {
        jobs: jobs as Record<string, WorkflowJob>,
    };
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

export const getWorkflowJob = (
    workflow: ReleaseWorkflow,
    jobName: string,
): WorkflowJob => {
    const job = workflow.jobs?.[jobName];

    if (!isRecord(job)) {
        throw new Error(`Release workflow is missing job ${jobName}.`);
    }

    return job;
};

export const getWorkflowJobSteps = (
    workflow: ReleaseWorkflow,
    jobName: string,
): WorkflowStep[] => {
    const job = getWorkflowJob(workflow, jobName);

    if (!Array.isArray(job.steps)) {
        return [];
    }

    return job.steps.filter(isWorkflowStep);
};

export const extractWithScalarValue = (
    step: WorkflowStep,
    key: string,
): string | undefined => {
    const withValue = step.with?.[key];

    if (typeof withValue !== 'string') {
        return undefined;
    }

    const trimmedValue = withValue.trim();

    return trimmedValue === '' ? undefined : stripWrappingQuotes(trimmedValue);
};

export const extractWithListValues = (
    step: WorkflowStep,
    key: string,
): string[] => {
    const withValue = step.with?.[key];

    if (Array.isArray(withValue)) {
        return withValue
            .filter((value): value is string => typeof value === 'string')
            .map((value) => stripWrappingQuotes(value.trim()))
            .filter((value) => value !== '');
    }

    if (typeof withValue !== 'string') {
        return [];
    }

    return withValue
        .split(/\r?\n/u)
        .map((line) => stripWrappingQuotes(line.trim()))
        .filter((line) => line !== '');
};

export const findArtifactStep = (
    workflow: ReleaseWorkflow,
    jobName: string,
    usesReference: string,
    artifactName: string,
): WorkflowStep | undefined => {
    return getWorkflowJobSteps(workflow, jobName).find((step) => {
        return (
            step.uses === usesReference &&
            extractWithScalarValue(step, 'name') === artifactName
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
    let workflow: ReleaseWorkflow;

    try {
        workflow = parseReleaseWorkflow(workflowText);
    } catch (error) {
        return [error instanceof Error ? error.message : String(error)];
    }

    try {
        const uploadArtifactStep = findArtifactStep(
            workflow,
            'prepare-release',
            'actions/upload-artifact@v7.0.1',
            releaseArtifactName,
        );

        if (uploadArtifactStep === undefined) {
            failures.push(
                `prepare-release is missing an upload-artifact step for ${releaseArtifactName}.`,
            );
        } else {
            artifactUploadPaths = extractWithListValues(
                uploadArtifactStep,
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
            const downloadArtifactStep = findArtifactStep(
                workflow,
                jobName,
                'actions/download-artifact@v8.0.1',
                releaseArtifactName,
            );

            if (downloadArtifactStep === undefined) {
                failures.push(
                    `${jobName} is missing a download-artifact step for ${releaseArtifactName}.`,
                );
                continue;
            }

            const downloadPath = extractWithScalarValue(
                downloadArtifactStep,
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

export const getReleaseWorkflowPath = (
    projectRoot: string = repoRoot,
): string => path.resolve(projectRoot, '.github', 'workflows', 'release.yml');

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
