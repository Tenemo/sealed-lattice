import {
    copyFile,
    cp,
    mkdir,
    readFile,
    readdir,
    writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));

/** @param {string} packageJsonText */
export const sanitizePublicPackageJson = (packageJsonText) => {
    const packageJson = JSON.parse(packageJsonText);
    delete packageJson.devDependencies;
    delete packageJson.scripts;

    return `${JSON.stringify(packageJson, null, 4)}\n`;
};

/**
 * @param {readonly string[]} arguments_
 * @param {string} optionName
 * @returns {string | undefined}
 */
const readOptionValue = (arguments_, optionName) => {
    const optionIndex = arguments_.indexOf(optionName);
    if (optionIndex === -1) {
        return undefined;
    }

    const optionValue = arguments_[optionIndex + 1];
    if (optionValue === undefined || optionValue.startsWith('--')) {
        throw new Error(`${optionName} requires a value.`);
    }
    return optionValue;
};

/** @param {readonly string[]} arguments_ */
export const parseStagePublicPackageArguments = (arguments_) => {
    const destinationPath = readOptionValue(arguments_, '--out');
    if (destinationPath === undefined) {
        throw new Error(
            'Usage: node ./tools/ci/stage-public-package.mjs --out <directory>',
        );
    }
    return { destinationPath };
};

/** @param {string} destinationPath */
const ensureEmptyDestination = async (destinationPath) => {
    await mkdir(destinationPath, { recursive: true });
    if ((await readdir(destinationPath)).length > 0) {
        throw new Error(
            `Public package staging directory must be empty: ${destinationPath}`,
        );
    }
};

/**
 * @param {{ destinationPath: string; projectRoot?: string }} input
 */
export const stagePublicPackage = async (input) => {
    const { destinationPath, projectRoot = repositoryRoot } = input;
    if (typeof destinationPath !== 'string' || destinationPath.length === 0) {
        throw new Error('Public package staging requires a destination path.');
    }

    const packageDirectory = path.resolve(projectRoot, 'packages', 'sdk');
    const resolvedDestinationPath = path.resolve(destinationPath);
    await ensureEmptyDestination(resolvedDestinationPath);

    await Promise.all([
        cp(
            path.join(packageDirectory, 'dist'),
            path.join(resolvedDestinationPath, 'dist'),
            { recursive: true },
        ),
        writeFile(
            path.join(resolvedDestinationPath, 'package.json'),
            sanitizePublicPackageJson(
                await readFile(
                    path.join(packageDirectory, 'package.json'),
                    'utf8',
                ),
            ),
            'utf8',
        ),
        copyFile(
            path.join(projectRoot, 'README.md'),
            path.join(resolvedDestinationPath, 'README.md'),
        ),
        copyFile(
            path.join(projectRoot, 'LICENSE'),
            path.join(resolvedDestinationPath, 'LICENSE'),
        ),
    ]);

    return { packageDirectory: resolvedDestinationPath };
};

const scriptEntryPoint = process.argv[1];
if (
    scriptEntryPoint !== undefined &&
    import.meta.url === pathToFileURL(scriptEntryPoint).href
) {
    const stagedPackage = await stagePublicPackage(
        parseStagePublicPackageArguments(process.argv.slice(2)),
    );
    console.log(`Staged public package: ${stagedPackage.packageDirectory}`);
}
