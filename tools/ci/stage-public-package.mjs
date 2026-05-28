import {
    copyFile,
    cp,
    mkdir,
    readFile,
    readdir,
    writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * @typedef {object} StagePublicPackageInput
 * @property {string} destinationPath
 * @property {string} [projectRoot]
 */

/**
 * @typedef {object} PublicPackageMetadata
 * @property {string} description
 */

/**
 * @typedef {object} StagedPublicPackage
 * @property {string} packageDirectory
 * @property {string} packageJsonPath
 * @property {string} readmePath
 */

/** @type {string} */
export const repoRoot = fileURLToPath(new URL('../../', import.meta.url));

/**
 * @param {string} [projectRoot]
 * @returns {string}
 */
export const getPublicPackageDirectory = (projectRoot = repoRoot) =>
    path.resolve(projectRoot, 'packages', 'sdk');

/**
 * @param {string} [projectRoot]
 * @returns {string}
 */
export const getRootReadmePath = (projectRoot = repoRoot) =>
    path.resolve(projectRoot, 'README.md');

/**
 * @param {string} [projectRoot]
 * @returns {string}
 */
export const getRootPackageJsonPath = (projectRoot = repoRoot) =>
    path.resolve(projectRoot, 'package.json');

const requiredPackageEntries = [
    'package.json',
    'LICENSE',
    'public-surface.json',
    'dist',
];

/**
 * @param {string} packageJsonText
 * @param {PublicPackageMetadata} publicPackageMetadata
 * @returns {string}
 */
export const sanitizePublicPackageJson = (
    packageJsonText,
    publicPackageMetadata,
) => {
    const packageJson = JSON.parse(packageJsonText);

    packageJson.description = publicPackageMetadata.description;

    delete packageJson.devDependencies;
    delete packageJson.scripts;

    return `${JSON.stringify(packageJson, null, 4)}\n`;
};

/**
 * @param {string} projectRoot
 * @returns {Promise<PublicPackageMetadata>}
 */
export const readPublicPackageMetadata = async (projectRoot = repoRoot) => {
    const rootPackageJson = JSON.parse(
        await readFile(getRootPackageJsonPath(projectRoot), 'utf8'),
    );
    if (
        typeof rootPackageJson.description !== 'string' ||
        rootPackageJson.description.length === 0
    ) {
        throw new Error('Root package.json must define package description.');
    }

    return {
        description: rootPackageJson.description,
    };
};

/**
 * @param {string} destinationPath
 * @returns {Promise<void>}
 */
const ensureEmptyDestination = async (destinationPath) => {
    await mkdir(destinationPath, { recursive: true });
    const destinationEntries = await readdir(destinationPath);
    if (destinationEntries.length > 0) {
        throw new Error(
            `Public package staging directory must be empty: ${destinationPath}`,
        );
    }
};

/**
 * @param {StagePublicPackageInput} input
 * @returns {Promise<StagedPublicPackage>}
 */
export const stagePublicPackage = async (input) => {
    const { destinationPath, projectRoot = repoRoot } = input;

    if (typeof destinationPath !== 'string' || destinationPath.length === 0) {
        throw new Error('Public package staging requires a destination path.');
    }

    const publicPackageDirectory = getPublicPackageDirectory(projectRoot);
    const resolvedDestinationPath = path.resolve(destinationPath);
    const publicPackageMetadata = await readPublicPackageMetadata(projectRoot);

    await ensureEmptyDestination(resolvedDestinationPath);

    for (const packageEntry of requiredPackageEntries) {
        const sourcePath = path.join(publicPackageDirectory, packageEntry);
        const destinationEntryPath = path.join(
            resolvedDestinationPath,
            packageEntry,
        );

        if (packageEntry === 'dist') {
            await cp(sourcePath, destinationEntryPath, { recursive: true });
        } else if (packageEntry === 'package.json') {
            await writeFile(
                destinationEntryPath,
                sanitizePublicPackageJson(
                    await readFile(sourcePath, 'utf8'),
                    publicPackageMetadata,
                ),
                'utf8',
            );
        } else {
            await copyFile(sourcePath, destinationEntryPath);
        }
    }

    await copyFile(
        getRootReadmePath(projectRoot),
        path.join(resolvedDestinationPath, 'README.md'),
    );

    return {
        packageDirectory: resolvedDestinationPath,
        packageJsonPath: path.join(resolvedDestinationPath, 'package.json'),
        readmePath: path.join(resolvedDestinationPath, 'README.md'),
    };
};
