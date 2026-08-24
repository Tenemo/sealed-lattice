import { createHash } from 'node:crypto';
import { mkdir, readFile, readdir, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { runWithLocalRunLog } from './local-run-log.js';
import { runCommandAndCaptureOutput } from './run-command.js';
import {
    buildSelectedLatticeEstimatorInput,
    canonicalJsonText,
    parseJsonValue,
    selectedLatticeEstimatorContainerImage,
    selectedLatticeEstimatorRevision,
    selectedLatticeEstimatorSourceTreeSha256,
    selectedLatticeEvidencePath,
    selectedLatticeRepositoryRoot,
    validateSelectedLatticeEvidence,
    type JsonValue,
} from './selected-lattice-security-evidence.js';

export type SelectedLatticeEvidenceArguments = {
    readonly writeRecord: boolean;
};

export const parseSelectedLatticeEvidenceArguments = (
    commandArguments: readonly string[],
): SelectedLatticeEvidenceArguments => {
    const normalizedArguments = commandArguments.filter(
        (argument) => argument !== '--',
    );
    if (normalizedArguments.length === 0) {
        return { writeRecord: false };
    }
    if (
        normalizedArguments.length === 1 &&
        normalizedArguments[0] === '--write-record'
    ) {
        return { writeRecord: true };
    }
    throw new Error(
        'The lattice-security evidence runner accepts only --write-record.',
    );
};

const collectSourceFiles = async (
    sourceRootPath: string,
    relativeDirectoryPath = '',
): Promise<readonly string[]> => {
    const directoryPath = path.join(sourceRootPath, relativeDirectoryPath);
    const entries = await readdir(directoryPath, { withFileTypes: true });
    const files: string[] = [];
    for (const entry of entries.sort((left, right) =>
        left.name < right.name ? -1 : left.name > right.name ? 1 : 0,
    )) {
        if (entry.name === '.git') {
            continue;
        }
        const relativePath = path.join(relativeDirectoryPath, entry.name);
        if (entry.isSymbolicLink()) {
            throw new Error(
                `The estimator source tree contains symbolic link ${relativePath}.`,
            );
        }
        if (entry.isDirectory()) {
            files.push(
                ...(await collectSourceFiles(sourceRootPath, relativePath)),
            );
        } else if (entry.isFile()) {
            files.push(relativePath);
        } else {
            throw new Error(
                `The estimator source tree contains unsupported entry ${relativePath}.`,
            );
        }
    }
    return files;
};

export const estimatorSourceTreeSha256 = async (
    sourceRootPath: string,
): Promise<string> => {
    const sourceRoot = await stat(sourceRootPath);
    if (!sourceRoot.isDirectory()) {
        throw new Error('The estimator source root is not a directory.');
    }
    const digest = createHash('sha256');
    const relativePaths = (await collectSourceFiles(sourceRootPath))
        .map((relativePath) => relativePath.split(path.sep).join('/'))
        .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
    if (relativePaths.length === 0) {
        throw new Error('The estimator source tree is empty.');
    }
    for (const relativePath of relativePaths) {
        digest.update(relativePath, 'utf8');
        digest.update(Buffer.from([0]));
        digest.update(
            await readFile(
                path.join(sourceRootPath, ...relativePath.split('/')),
            ),
        );
        digest.update(Buffer.from([0]));
    }
    return digest.digest('hex');
};

const dockerBindMount = (input: {
    readonly sourcePath: string;
    readonly targetPath: string;
}): string => {
    if (input.sourcePath.includes(',')) {
        throw new Error(
            `Docker bind source ${input.sourcePath} contains an unsupported comma.`,
        );
    }
    return `type=bind,source=${input.sourcePath},target=${input.targetPath},readonly`;
};

export const buildSelectedLatticeEstimatorDockerArguments = (input: {
    readonly estimatorInputPath: string;
    readonly estimatorSourceRootPath: string;
    readonly repositoryRootPath: string;
}): readonly string[] => {
    const relativeInputPath = path.relative(
        input.repositoryRootPath,
        input.estimatorInputPath,
    );
    if (
        relativeInputPath === '' ||
        relativeInputPath === '..' ||
        relativeInputPath.startsWith(`..${path.sep}`) ||
        path.isAbsolute(relativeInputPath)
    ) {
        throw new Error('The estimator input must stay inside the repository.');
    }
    const containerInputPath = `/workspace/${relativeInputPath
        .split(path.sep)
        .join('/')}`;
    return [
        'run',
        '--rm',
        '--network',
        'none',
        '--entrypoint',
        '/usr/bin/sage',
        '--mount',
        dockerBindMount({
            sourcePath: input.repositoryRootPath,
            targetPath: '/workspace',
        }),
        '--mount',
        dockerBindMount({
            sourcePath: input.estimatorSourceRootPath,
            targetPath: '/lattice-estimator',
        }),
        '--env',
        'PYTHONPATH=/lattice-estimator',
        '--env',
        `SEALED_LATTICE_ESTIMATOR_REVISION=${selectedLatticeEstimatorRevision}`,
        '--env',
        `SEALED_LATTICE_ESTIMATOR_CONTAINER_IMAGE=${selectedLatticeEstimatorContainerImage}`,
        '--env',
        'SEALED_LATTICE_ESTIMATOR_SOURCE_ROOT=/lattice-estimator',
        '--workdir',
        '/workspace',
        selectedLatticeEstimatorContainerImage,
        '--python',
        '/workspace/tools/ci/selected-lattice-security-estimator.py',
        '--input',
        containerInputPath,
    ];
};

const requireSuccessfulCommand = (input: {
    readonly commandDescription: string;
    readonly exitCode: number;
    readonly stderr: string;
    readonly terminationSignal: NodeJS.Signals | null;
}): void => {
    if (input.exitCode === 0 && input.terminationSignal === null) {
        return;
    }
    throw new Error(
        `${input.commandDescription} failed with exit code ${input.exitCode}, signal ${input.terminationSignal ?? 'none'}. ${input.stderr.trim()}`,
    );
};

const readCheckedEvidence = async (): Promise<JsonValue> =>
    parseJsonValue(await readFile(selectedLatticeEvidencePath, 'utf8'));

const formattedEvidence = (value: JsonValue): string =>
    `${JSON.stringify(value, undefined, 2)}\n`;

export const runSelectedLatticeSecurityEvidence = async (
    rawArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    await runWithLocalRunLog(
        {
            commandLineArguments: rawArguments,
            lanes: ['Selected lattice-security evidence'],
            scriptName: 'evidence:lattice-security',
        },
        async (runLog) => {
            const parsedArguments =
                parseSelectedLatticeEvidenceArguments(rawArguments);
            const defaultEstimatorSourceRoot = path.join(
                selectedLatticeRepositoryRoot,
                'reference-projects',
                `lattice-estimator-${selectedLatticeEstimatorRevision}`,
            );
            const estimatorSourceRootPath = path.resolve(
                process.env.SEALED_LATTICE_ESTIMATOR_SOURCE_ROOT ??
                    defaultEstimatorSourceRoot,
            );
            const sourceTreeDigest = await estimatorSourceTreeSha256(
                estimatorSourceRootPath,
            );
            if (sourceTreeDigest !== selectedLatticeEstimatorSourceTreeSha256) {
                throw new Error(
                    `The estimator source tree must be ${selectedLatticeEstimatorSourceTreeSha256}, found ${sourceTreeDigest}.`,
                );
            }
            const revisionResult = await runCommandAndCaptureOutput(
                {
                    args: ['-C', estimatorSourceRootPath, 'rev-parse', 'HEAD'],
                    command: 'git',
                    description: 'verify pinned lattice-estimator revision',
                    logFileSlug: 'lattice-estimator-revision',
                    workingDirectoryPath: selectedLatticeRepositoryRoot,
                },
                { runLog },
            );
            requireSuccessfulCommand({
                commandDescription: 'Estimator revision verification',
                ...revisionResult,
            });
            if (
                revisionResult.stdout.trim() !==
                selectedLatticeEstimatorRevision
            ) {
                throw new Error(
                    `The estimator checkout must be ${selectedLatticeEstimatorRevision}, found ${revisionResult.stdout.trim()}.`,
                );
            }
            const imageResult = await runCommandAndCaptureOutput(
                {
                    args: [
                        'image',
                        'inspect',
                        selectedLatticeEstimatorContainerImage,
                    ],
                    command: 'docker',
                    description: 'verify pinned Sage container image',
                    logFileSlug: 'lattice-estimator-container-image',
                    workingDirectoryPath: selectedLatticeRepositoryRoot,
                },
                { runLog },
            );
            requireSuccessfulCommand({
                commandDescription: 'Pinned Sage container image verification',
                ...imageResult,
            });

            const attachmentDirectoryPath = path.join(
                runLog.runDirectoryPath,
                'attachments',
                'selected-lattice-security',
            );
            await mkdir(attachmentDirectoryPath, { recursive: true });
            const estimatorInput = await buildSelectedLatticeEstimatorInput();
            const estimatorInputPath = path.join(
                attachmentDirectoryPath,
                'estimator-input.json',
            );
            await writeFile(
                estimatorInputPath,
                formattedEvidence(estimatorInput),
                'utf8',
            );
            const estimatorResult = await runCommandAndCaptureOutput(
                {
                    args: buildSelectedLatticeEstimatorDockerArguments({
                        estimatorInputPath,
                        estimatorSourceRootPath,
                        repositoryRootPath: selectedLatticeRepositoryRoot,
                    }),
                    command: 'docker',
                    description:
                        'run selected lattice-security estimator attacks',
                    logFileSlug: 'selected-lattice-security-estimator',
                    workingDirectoryPath: selectedLatticeRepositoryRoot,
                },
                { runLog },
            );
            requireSuccessfulCommand({
                commandDescription: 'Selected lattice-security estimator',
                ...estimatorResult,
            });
            const freshEvidence = parseJsonValue(estimatorResult.stdout);
            const summary = validateSelectedLatticeEvidence(
                freshEvidence,
                estimatorInput,
            );
            const freshEvidencePath = path.join(
                attachmentDirectoryPath,
                'fresh-estimator-evidence.json',
            );
            await writeFile(
                freshEvidencePath,
                formattedEvidence(freshEvidence),
                'utf8',
            );
            if (parsedArguments.writeRecord) {
                await writeFile(
                    selectedLatticeEvidencePath,
                    formattedEvidence(freshEvidence),
                    'utf8',
                );
            } else {
                const checkedEvidence = await readCheckedEvidence();
                validateSelectedLatticeEvidence(
                    checkedEvidence,
                    estimatorInput,
                );
                if (
                    canonicalJsonText(checkedEvidence) !==
                    canonicalJsonText(freshEvidence)
                ) {
                    throw new Error(
                        'Fresh estimator output does not match the checked evidence record.',
                    );
                }
            }
            const summaryLine =
                `Selected lattice-security estimator minimums: ` +
                `${summary.minimumClassicalSecurityBitsLowerBound} classical bits, ` +
                `${summary.minimumQuantumSecurityBitsLowerBound} quantum bits.`;
            console.log(summaryLine);
            runLog.writeCombinedOutput(`${summaryLine}\n`);
        },
    );
};

if (import.meta.main) {
    void runSelectedLatticeSecurityEvidence();
}
