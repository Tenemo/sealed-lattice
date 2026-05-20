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
 * @typedef {object} StagedPublicPackage
 * @property {string} packageDirectory
 * @property {string} packageJsonPath
 * @property {string} readmePath
 */

/**
 * @typedef {object} StagePublicPackageArguments
 * @property {string} destinationPath
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

const requiredPackageEntries = [
    'package.json',
    'LICENSE',
    'public-surface.json',
    'dist',
];

/**
 * @param {string} packageJsonText
 * @returns {string}
 */
export const sanitizePublicPackageJson = (packageJsonText) => {
    const packageJson = JSON.parse(packageJsonText);

    delete packageJson.devDependencies;
    delete packageJson.scripts;

    return `${JSON.stringify(packageJson, null, 4)}\n`;
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
        throw new Error('Public package staging requires --out');
    }

    const publicPackageDirectory = getPublicPackageDirectory(projectRoot);
    const resolvedDestinationPath = path.resolve(destinationPath);

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
                sanitizePublicPackageJson(await readFile(sourcePath, 'utf8')),
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

/**
 * @param {string[]} commandLineArguments
 * @returns {StagePublicPackageArguments}
 */
export const parseStagePublicPackageArguments = (commandLineArguments) => {
    const outputIndex = commandLineArguments.indexOf('--out');
    if (outputIndex === -1) {
        throw new Error('Public package staging requires --out');
    }

    const destinationPath = commandLineArguments[outputIndex + 1];
    if (destinationPath === undefined || destinationPath.length === 0) {
        throw new Error('Public package staging requires --out');
    }

    return { destinationPath };
};

/**
 * @returns {Promise<void>}
 */
const main = async () => {
    const { destinationPath } = parseStagePublicPackageArguments(
        process.argv.slice(2),
    );
    const { packageDirectory } = await stagePublicPackage({ destinationPath });

    console.log(packageDirectory);
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    void main();
}
